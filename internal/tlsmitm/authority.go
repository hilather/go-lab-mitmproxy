package tlsmitm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

const (
	// ALPN is the only advertised protocol on minted leaves and upstream.
	ALPN = "http/1.1"

	leafCacheCap   = 256
	caValidity     = 10 * 365 * 24 * time.Hour
	leafValidity   = 24 * time.Hour
	notBeforeSkew  = 5 * time.Minute
	minRSABits     = 2048
	caCommonName   = "LabMITM Lab CA"
	caOrganization = "LabMITM"
	caOrgUnit      = "laboratory-only"
)

// Result tokens stored on Flow.Error and tls intercept metrics.
const (
	ResultOK                 = "ok"
	ResultMintFail           = "mint_fail"
	ResultTLSHandshake       = "tls_handshake"
	ResultUpstreamTLS        = "upstream_tls"
	ResultUpstreamVerifyFail = "upstream_verify_fail"
	ResultHTTP2Inner         = "http2_inner"
)

var (
	// ErrEmptyName is returned when SNI and CONNECT host are both empty.
	ErrEmptyName = errors.New("tlsmitm: empty SNI and CONNECT host")
	// ErrEmptyKey is returned when a files-mode key PEM is empty.
	ErrEmptyKey = errors.New("tlsmitm: CA key PEM must not be empty")
	// ErrWorldWritable is returned when a files-mode key is world-writable.
	ErrWorldWritable = errors.New("tlsmitm: CA key file must not be world-writable")
	// ErrNotCA is returned when the loaded cert is not a signing CA.
	ErrNotCA = errors.New("tlsmitm: certificate is not a CA")
	// ErrKeyType is returned when the CA key is not RSA≥2048 or P-256/P-384.
	ErrKeyType = errors.New("tlsmitm: CA key must be RSA ≥2048 or ECDSA P-256/P-384")
)

var nextProtos = []string{ALPN}

// Options construct an Authority (generate-in-memory or load PEM files).
type Options struct {
	Mode               string
	CertFile           string
	KeyFile            string
	InsecureSkipVerify bool
	ExtraCAFiles       []string
}

// Authority is an in-process lab CA plus a per-host leaf cache.
// It never logs or exports the CA private key.
type Authority struct {
	mu       sync.Mutex
	mode     string
	caCert   *x509.Certificate
	caKey    crypto.Signer
	certPEM  []byte
	cache    *leafCache
	roots    *x509.CertPool
	insecure bool
}

// New generates or loads a lab CA. Key PEM bytes are discarded after parse.
func New(opts Options) (*Authority, error) {
	mode := strings.TrimSpace(opts.Mode)
	if mode == "" {
		mode = model.CAModeGenerate
	}
	var a *Authority
	var err error
	switch mode {
	case model.CAModeGenerate:
		if strings.TrimSpace(opts.CertFile) != "" || strings.TrimSpace(opts.KeyFile) != "" {
			return nil, errors.New("tlsmitm: certFile/keyFile are illegal when mode is generate")
		}
		a, err = generate()
	case model.CAModeFiles:
		a, err = loadFiles(opts.CertFile, opts.KeyFile)
	default:
		return nil, fmt.Errorf("tlsmitm: unknown ca mode %q", mode)
	}
	if err != nil {
		return nil, err
	}
	a.mode = mode
	a.insecure = opts.InsecureSkipVerify
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	for _, f := range opts.ExtraCAFiles {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		pemBytes, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("tlsmitm: extraCAFile %s: %w", f, err)
		}
		if !roots.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("tlsmitm: extraCAFile %s: no certificates", f)
		}
	}
	a.roots = roots
	return a, nil
}

func generate() (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlsmitm: generate CA key: %w", err)
	}
	serial, err := serial128()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         caCommonName,
			Organization:       []string{caOrganization},
			OrganizationalUnit: []string{caOrgUnit},
		},
		NotBefore:             now.Add(-notBeforeSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("tlsmitm: create CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("tlsmitm: parse CA: %w", err)
	}
	return newAuthority(model.CAModeGenerate, cert, key), nil
}

func loadFiles(certFile, keyFile string) (*Authority, error) {
	if strings.TrimSpace(certFile) == "" || strings.TrimSpace(keyFile) == "" {
		return nil, errors.New("tlsmitm: mode files requires certFile and keyFile")
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlsmitm: stat key: %w", err)
	}
	if info.Mode().Perm()&0o002 != 0 {
		return nil, ErrWorldWritable
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("tlsmitm: read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlsmitm: read key: %w", err)
	}
	defer clearBytes(keyPEM)
	if len(bytesTrimSpace(keyPEM)) == 0 {
		return nil, ErrEmptyKey
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tlsmitm: parse CA: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("tlsmitm: CA cert missing")
	}
	parsed, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("tlsmitm: parse CA cert: %w", err)
	}
	if !parsed.BasicConstraintsValid || !parsed.IsCA || parsed.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, ErrNotCA
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, ErrKeyType
	}
	if err := checkCAKey(signer); err != nil {
		return nil, err
	}
	return newAuthority(model.CAModeFiles, parsed, signer), nil
}

func newAuthority(mode string, cert *x509.Certificate, key crypto.Signer) *Authority {
	return &Authority{
		mode:    mode,
		caCert:  cert,
		caKey:   key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		cache:   newLeafCache(leafCacheCap),
	}
}

func checkCAKey(key crypto.Signer) error {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N == nil || k.N.BitLen() < minRSABits {
			return ErrKeyType
		}
		return nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384():
			return nil
		default:
			return ErrKeyType
		}
	default:
		return ErrKeyType
	}
}

func serial128() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("tlsmitm: serial: %w", err)
	}
	return new(big.Int).SetBytes(b), nil
}

func clearBytes(p []byte) {
	for i := range p {
		p[i] = 0
	}
}

func bytesTrimSpace(p []byte) []byte {
	return []byte(strings.TrimSpace(string(p)))
}

// CertPEM returns the CA certificate PEM only. Never the private key.
func (a *Authority) CertPEM() []byte {
	if a == nil {
		return nil
	}
	out := make([]byte, len(a.certPEM))
	copy(out, a.certPEM)
	return out
}

// CertPool is a pool containing only the lab CA. For tests and extraCAs.
func (a *Authority) CertPool() *x509.CertPool {
	if a == nil || a.caCert == nil {
		return x509.NewCertPool()
	}
	pool := x509.NewCertPool()
	pool.AddCert(a.caCert)
	return pool
}

// Status is GET /v1/status CA metadata. It never includes key material.
func (a *Authority) Status() model.CAStatus {
	if a == nil || a.caCert == nil {
		return model.CAStatus{Mode: "off"}
	}
	sum := sha256.Sum256(a.caCert.RawSubjectPublicKeyInfo)
	return model.CAStatus{
		Mode:       a.mode,
		SPKISHA256: hex.EncodeToString(sum[:]),
		Subject:    a.caCert.Subject.String(),
		NotAfter:   a.caCert.NotAfter,
	}
}

// InsecureSkipVerify reports the upstream verify opt-in.
func (a *Authority) InsecureSkipVerify() bool {
	return a != nil && a.insecure
}

// CACertificate is the parsed lab CA. Tests inspect the frozen template.
func (a *Authority) CACertificate() *x509.Certificate {
	if a == nil {
		return nil
	}
	return a.caCert
}

// String omits key material so slog / fmt cannot dump the signer.
func (a *Authority) String() string {
	if a == nil || a.caCert == nil {
		return "tlsmitm.Authority<nil>"
	}
	return fmt.Sprintf("tlsmitm.Authority{mode:%s subject:%q}", a.mode, a.caCert.Subject.String())
}

// GoString is the %#v form of String (no key material).
func (a *Authority) GoString() string {
	return a.String()
}

package tlsmitm

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestGenerateCATemplate(t *testing.T) {
	a, err := New(Options{Mode: model.CAModeGenerate})
	if err != nil {
		t.Fatal(err)
	}
	c := a.CACertificate()
	if c == nil {
		t.Fatal("nil CA")
	}
	if c.Subject.CommonName != caCommonName {
		t.Fatalf("CN=%q", c.Subject.CommonName)
	}
	if len(c.Subject.Organization) == 0 || c.Subject.Organization[0] != caOrganization {
		t.Fatalf("O=%v", c.Subject.Organization)
	}
	if len(c.Subject.OrganizationalUnit) == 0 || c.Subject.OrganizationalUnit[0] != caOrgUnit {
		t.Fatalf("OU=%v", c.Subject.OrganizationalUnit)
	}
	if !c.IsCA || !c.BasicConstraintsValid {
		t.Fatal("not a CA")
	}
	if c.MaxPathLen != 0 || !c.MaxPathLenZero {
		t.Fatalf("MaxPathLen=%d zero=%v", c.MaxPathLen, c.MaxPathLenZero)
	}
	if c.KeyUsage&x509.KeyUsageCertSign == 0 || c.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Fatalf("KeyUsage=%v", c.KeyUsage)
	}
	now := time.Now()
	if c.NotBefore.After(now) || c.NotAfter.Before(now.Add(9*365*24*time.Hour)) {
		t.Fatalf("validity %v..%v", c.NotBefore, c.NotAfter)
	}
	pem := a.CertPEM()
	if !bytes.Contains(pem, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("CertPEM missing CERTIFICATE")
	}
	if bytes.Contains(bytes.ToUpper(pem), []byte("PRIVATE")) {
		t.Fatal("CertPEM contained PRIVATE")
	}
	st := a.Status()
	if st.Mode != model.CAModeGenerate || st.SPKISHA256 == "" || st.Subject == "" {
		t.Fatalf("status %+v", st)
	}
}

func TestLoadFilesCA(t *testing.T) {
	a, err := New(Options{
		Mode:     model.CAModeFiles,
		CertFile: testdataTLS(t, "ca.pem"),
		KeyFile:  testdataTLS(t, "ca-key.pem"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.Status().Mode != model.CAModeFiles {
		t.Fatalf("mode %q", a.Status().Mode)
	}
	if !a.CACertificate().IsCA {
		t.Fatal("loaded cert is not CA")
	}
}

func TestLoadFilesRejects(t *testing.T) {
	t.Run("empty key", func(t *testing.T) {
		_, err := New(Options{
			Mode:     model.CAModeFiles,
			CertFile: testdataTLS(t, "ca.pem"),
			KeyFile:  testdataTLS(t, "empty-key.pem"),
		})
		if err == nil || !strings.Contains(err.Error(), "empty") && err != ErrEmptyKey {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("world writable", func(t *testing.T) {
		dir := t.TempDir()
		src, err := os.ReadFile(testdataTLS(t, "ca-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		key := filepath.Join(dir, "ca-key.pem")
		if err := os.WriteFile(key, src, 0o666); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(key, 0o666); err != nil {
			t.Fatal(err)
		}
		_, err = New(Options{
			Mode:     model.CAModeFiles,
			CertFile: testdataTLS(t, "ca.pem"),
			KeyFile:  key,
		})
		if err != ErrWorldWritable {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("not a CA", func(t *testing.T) {
		_, err := New(Options{
			Mode:     model.CAModeFiles,
			CertFile: testdataTLS(t, "not-ca.pem"),
			KeyFile:  testdataTLS(t, "not-ca-key.pem"),
		})
		if err != ErrNotCA {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("rsa too small", func(t *testing.T) {
		cert, key := mustTempRSA(t, 1024, true)
		_, err := New(Options{Mode: model.CAModeFiles, CertFile: cert, KeyFile: key})
		if err != ErrKeyType {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestGenerateRejectsUnusedFiles(t *testing.T) {
	_, err := New(Options{
		Mode:     model.CAModeGenerate,
		CertFile: testdataTLS(t, "ca.pem"),
		KeyFile:  testdataTLS(t, "ca-key.pem"),
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMintSANAndCache(t *testing.T) {
	a, err := New(Options{Mode: model.CAModeGenerate})
	if err != nil {
		t.Fatal(err)
	}
	c1, err := a.Mint("App.Lab")
	if err != nil {
		t.Fatal(err)
	}
	if c1.Leaf == nil || len(c1.Leaf.DNSNames) != 1 || c1.Leaf.DNSNames[0] != "app.lab" {
		t.Fatalf("DNSNames=%v", c1.Leaf.DNSNames)
	}
	if c1.Leaf.Subject.CommonName != "app.lab" {
		t.Fatalf("CN=%q", c1.Leaf.Subject.CommonName)
	}
	if c1.Leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("missing DigitalSignature")
	}
	if len(c1.Leaf.ExtKeyUsage) != 1 || c1.Leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("ExtKeyUsage=%v", c1.Leaf.ExtKeyUsage)
	}
	c2, err := a.Mint("app.lab")
	if err != nil {
		t.Fatal(err)
	}
	if c1.Leaf.SerialNumber.Cmp(c2.Leaf.SerialNumber) != 0 {
		t.Fatal("same host minted twice")
	}
	ipLeaf, err := a.Mint("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ipLeaf.Leaf.IPAddresses) != 1 || ipLeaf.Leaf.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatalf("IPAddresses=%v", ipLeaf.Leaf.IPAddresses)
	}
	if _, err := a.Mint(""); err != ErrEmptyName {
		t.Fatalf("empty host err=%v", err)
	}
}

func TestLeafLRUEviction(t *testing.T) {
	a, err := New(Options{Mode: model.CAModeGenerate})
	if err != nil {
		t.Fatal(err)
	}
	a.cache.cap = 2
	first, err := a.Mint("a.lab")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Mint("b.lab"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Mint("c.lab"); err != nil {
		t.Fatal(err)
	}
	again, err := a.Mint("a.lab")
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Cmp(again.Leaf.SerialNumber) == 0 {
		t.Fatal("evicted host reused old leaf")
	}
}

func TestMintConcurrent(t *testing.T) {
	a, err := New(Options{Mode: model.CAModeGenerate})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := "app.lab"
			if i%2 == 0 {
				host = "other.lab"
			}
			if _, err := a.Mint(host); err != nil {
				t.Errorf("mint: %v", err)
			}
		}(i)
	}
	wg.Wait()
}

func TestNeverLogPrivateKey(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	a, err := New(Options{Mode: model.CAModeGenerate})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := a.Mint("app.lab")
	if err != nil {
		t.Fatal(err)
	}
	log.Info("authority", "a", a, "string", a.String(), "gostring", a.GoString(), "status", a.Status(), "pem", string(a.CertPEM()))
	log.Debug("leaf", "cn", leaf.Leaf.Subject.CommonName, "alpn", ALPN)
	// files-mode too
	f, err := New(Options{
		Mode:     model.CAModeFiles,
		CertFile: testdataTLS(t, "ca.pem"),
		KeyFile:  testdataTLS(t, "ca-key.pem"),
	})
	if err != nil {
		t.Fatal(err)
	}
	log.Info("files", "a", f, "pem", string(f.CertPEM()))
	out := strings.ToUpper(buf.String())
	if strings.Contains(out, "BEGIN") && strings.Contains(out, "PRIVATE") {
		t.Fatalf("log contained BEGIN PRIVATE:\n%s", buf.String())
	}
	if strings.Contains(out, "BEGIN PRIVATE") {
		t.Fatalf("log contained BEGIN PRIVATE:\n%s", buf.String())
	}
}

func TestALPNHTTP11Only(t *testing.T) {
	a, err := New(Options{Mode: model.CAModeGenerate})
	if err != nil {
		t.Fatal(err)
	}
	cfg := a.ServerConfig("app.lab")
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != ALPN {
		t.Fatalf("server NextProtos=%v", cfg.NextProtos)
	}
	up := a.UpstreamConfig("app.lab")
	if len(up.NextProtos) != 1 || up.NextProtos[0] != ALPN {
		t.Fatalf("upstream NextProtos=%v", up.NextProtos)
	}
	hello := &tls.ClientHelloInfo{ServerName: "app.lab"}
	got, err := cfg.GetConfigForClient(hello)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.NextProtos) != 1 || got.NextProtos[0] != "http/1.1" {
		t.Fatalf("leaf NextProtos=%v", got.NextProtos)
	}
	if got.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion=%d", got.MinVersion)
	}
}

func mustTempRSA(t *testing.T, bits int, isCA bool) (certPath, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "tiny-rsa"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "c.pem")
	keyPath = filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o644); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

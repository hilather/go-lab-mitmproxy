package tlsmitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"time"
)

type leafCache struct {
	cap   int
	order []string
	items map[string]*tls.Certificate
}

func newLeafCache(cap int) *leafCache {
	if cap <= 0 {
		cap = leafCacheCap
	}
	return &leafCache{cap: cap, items: make(map[string]*tls.Certificate)}
}

func (c *leafCache) get(host string) *tls.Certificate {
	cert, ok := c.items[host]
	if !ok {
		return nil
	}
	c.touch(host)
	return cert
}

func (c *leafCache) touch(host string) {
	for i, h := range c.order {
		if h == host {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	c.order = append(c.order, host)
}

func (c *leafCache) put(host string, cert *tls.Certificate) {
	if _, ok := c.items[host]; ok {
		c.items[host] = cert
		c.touch(host)
		return
	}
	for len(c.items) >= c.cap && len(c.order) > 0 {
		old := c.order[0]
		c.order = c.order[1:]
		delete(c.items, old)
	}
	c.items[host] = cert
	c.order = append(c.order, host)
}

// Mint returns a cached or newly minted leaf for host (SNI or CONNECT host).
func (a *Authority) Mint(host string) (*tls.Certificate, error) {
	return a.leafFor(host)
}

func (a *Authority) leafFor(host string) (*tls.Certificate, error) {
	if a == nil || a.caCert == nil || a.caKey == nil {
		return nil, errorsMint("CA is not initialized")
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, ErrEmptyName
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if cert := a.cache.get(host); cert != nil {
		return cert, nil
	}
	cert, err := a.mintLocked(host)
	if err != nil {
		return nil, err
	}
	a.cache.put(host, cert)
	return cert, nil
}

func errorsMint(msg string) error {
	return fmt.Errorf("tlsmitm: mint: %s", msg)
}

func (a *Authority) mintLocked(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlsmitm: leaf key: %w", err)
	}
	serial, err := serial128()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-notBeforeSkew),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.caCert, &key.PublicKey, a.caKey)
	if err != nil {
		return nil, fmt.Errorf("tlsmitm: create leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("tlsmitm: parse leaf: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, a.caCert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// LeafDNS returns DNS SANs of the minted (or cached) leaf for host.
func (a *Authority) LeafDNS(host string) []string {
	cert, err := a.leafFor(host)
	if err != nil || cert == nil || cert.Leaf == nil {
		return nil
	}
	out := make([]string, len(cert.Leaf.DNSNames))
	copy(out, cert.Leaf.DNSNames)
	return out
}

package http2x

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func h2TLSPair(t *testing.T) (client, server *tls.Conn) {
	t.Helper()
	cert := testCert(t)
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	type hs struct {
		c   *tls.Conn
		err error
	}
	sc := make(chan hs, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			sc <- hs{err: err}
			return
		}
		tc := tls.Server(c, &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{NextProtoH2},
			MinVersion:   tls.VersionTLS12,
		})
		sc <- hs{c: tc, err: tc.Handshake()}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client = tls.Client(raw, &tls.Config{
		ServerName: "app.lab",
		RootCAs:    pool,
		NextProtos: []string{NextProtoH2},
		MinVersion: tls.VersionTLS12,
	})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	got := <-sc
	if got.err != nil {
		t.Fatal(got.err)
	}
	server = got.c
	if client.ConnectionState().NegotiatedProtocol != NextProtoH2 {
		t.Fatalf("client ALPN=%q", client.ConnectionState().NegotiatedProtocol)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "app.lab"},
		DNSNames:     []string{"app.lab"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

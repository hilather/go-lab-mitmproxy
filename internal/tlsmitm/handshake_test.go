package tlsmitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"
)

func TestHandshakeTrustAndReject(t *testing.T) {
	a, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})
	errc := make(chan error, 1)
	go func() {
		sc, err := a.HandshakeServer(context.Background(), serverRaw, "app.lab")
		if err != nil {
			errc <- err
			return
		}
		_, _ = sc.Write([]byte("ok"))
		errc <- nil
	}()
	cfg := &tls.Config{
		ServerName: "app.lab",
		RootCAs:    a.CertPool(),
		NextProtos: []string{ALPN, "h2"},
		MinVersion: tls.VersionTLS12,
	}
	cc := tls.Client(clientRaw, cfg)
	if err := cc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if cc.ConnectionState().NegotiatedProtocol != ALPN {
		t.Fatalf("ALPN=%q", cc.ConnectionState().NegotiatedProtocol)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(cc, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ok" {
		t.Fatalf("payload %q", buf)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeUntrustedClientFails(t *testing.T) {
	a, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})
	go func() {
		_, _ = a.HandshakeServer(context.Background(), serverRaw, "app.lab")
	}()
	cc := tls.Client(clientRaw, &tls.Config{
		ServerName: "app.lab",
		RootCAs:    x509.NewCertPool(),
		MinVersion: tls.VersionTLS12,
	})
	_ = cc.SetDeadline(time.Now().Add(2 * time.Second))
	if err := cc.Handshake(); err == nil {
		t.Fatal("untrusted client succeeded")
	}
}

func TestHandshakeEmptyNameRejected(t *testing.T) {
	a, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := a.ServerConfig("")
	_, err = cfg.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != ErrEmptyName {
		t.Fatalf("err=%v", err)
	}
}

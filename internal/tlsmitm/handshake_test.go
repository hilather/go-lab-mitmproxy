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
		sc, err := a.HandshakeServer(context.Background(), serverRaw, "app.lab", nil)
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

func TestUpstreamConfigNilAuthority(t *testing.T) {
	var a *Authority
	cfg := a.UpstreamConfig("app.lab")
	if cfg == nil {
		t.Fatal("nil Authority must still return a tls.Config")
	}
	if cfg.ServerName != "app.lab" {
		t.Fatalf("ServerName=%q", cfg.ServerName)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("nil Authority must not skip verify")
	}
	if cfg.RootCAs != nil {
		t.Fatal("nil Authority must not set RootCAs")
	}
	live, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	live.insecure = true
	got := live.UpstreamConfig("origin.lab")
	if !got.InsecureSkipVerify {
		t.Fatal("insecure authority must set InsecureSkipVerify")
	}
	if got.RootCAs == nil {
		t.Fatal("live authority must attach RootCAs")
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
		_, _ = a.HandshakeServer(context.Background(), serverRaw, "app.lab", nil)
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

func TestHandshakeNextProtosFromArg(t *testing.T) {
	a, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})
	type result struct {
		alpn string
		err  error
	}
	donec := make(chan result, 1)
	go func() {
		sc, err := a.HandshakeServer(context.Background(), serverRaw, "app.lab", []string{"h2", ALPN})
		if err != nil {
			donec <- result{err: err}
			return
		}
		donec <- result{alpn: sc.ConnectionState().NegotiatedProtocol}
	}()
	cc := tls.Client(clientRaw, &tls.Config{
		ServerName: "app.lab",
		RootCAs:    a.CertPool(),
		NextProtos: []string{"h2", ALPN},
		MinVersion: tls.VersionTLS12,
	})
	if err := cc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if cc.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("client ALPN=%q", cc.ConnectionState().NegotiatedProtocol)
	}
	got := <-donec
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.alpn != "h2" {
		t.Fatalf("server ALPN=%q", got.alpn)
	}
}

func TestHandshakeEmptyNextProtosDefaultsHTTP11(t *testing.T) {
	a, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := a.serverConfig("app.lab", nil)
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != ALPN {
		t.Fatalf("NextProtos=%v", cfg.NextProtos)
	}
	up := a.upstreamConfig("app.lab", []string{})
	if len(up.NextProtos) != 1 || up.NextProtos[0] != ALPN {
		t.Fatalf("upstream NextProtos=%v", up.NextProtos)
	}
}

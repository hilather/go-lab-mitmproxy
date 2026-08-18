package proxy

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
)

func TestSOCKS5PeekCloses(t *testing.T) {
	px := startProxy(t, Options{})
	c, err := net.DialTimeout("tcp", px.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if n != 0 && err == nil {
		t.Fatalf("SOCKS got %q; want close", buf[:n])
	}
	if err == nil {
		t.Fatal("expected close after SOCKS greeting")
	}
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("socks") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("socks") < 1 {
		t.Fatal("expected socks reject metric")
	}
}

func TestSOCKS4PeekCloses(t *testing.T) {
	px := startProxy(t, Options{})
	c, err := net.DialTimeout("tcp", px.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	// SOCKS4 CONNECT 80 127.0.0.1 userid
	if _, err := c.Write([]byte{0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 0}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	_, err = c.Read(buf)
	if err == nil {
		t.Fatal("expected close after SOCKS4")
	}
}

func TestHTTP2PrefaceCloses(t *testing.T) {
	px := startProxy(t, Options{})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if err := c.WriteRaw([]byte(preface)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := c.Conn.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("HTTP/2 preface got response %q", buf[:n])
	}
	if err == nil {
		// drain via client reader
		_, err = c.ReadLine()
	}
	if err == nil {
		t.Fatal("expected connection close on HTTP/2 preface")
	}
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("http2") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("http2") < 1 {
		t.Fatal("expected http2 reject metric")
	}
}

func TestHTTP2PrefaceNotParsedAsRequest(t *testing.T) {
	px := startProxy(t, Options{})
	c, err := net.DialTimeout("tcp", px.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	b, err := io.ReadAll(c)
	if err == nil && len(b) > 0 && string(b[:min(12, len(b))]) == "HTTP/1.1 400" {
		t.Fatalf("preface became 400: %q", b)
	}
}

func TestSilentPeerDoesNotBlockAccept(t *testing.T) {
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	px := startProxy(t, Options{})
	silent, err := net.DialTimeout("tcp", px.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()

	tr := &http.Transport{
		Proxy:                 http.ProxyURL(mustURL(t, "http://"+px.Addr().String())),
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 2 * time.Second,
	}
	defer tr.CloseIdleConnections()
	req := mustRequest(t, http.MethodGet, originURL+"/hello")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("second client blocked by silent peer: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(b) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, b)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

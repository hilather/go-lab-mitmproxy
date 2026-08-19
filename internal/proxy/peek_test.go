package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
)

type tempNetErr struct{}

func (tempNetErr) Error() string   { return "temporary" }
func (tempNetErr) Timeout() bool   { return false }
func (tempNetErr) Temporary() bool { return true }

type stubListener struct {
	addr   net.Addr
	accept func() (net.Conn, error)
}

func (l *stubListener) Accept() (net.Conn, error) {
	if l == nil || l.accept == nil {
		return nil, net.ErrClosed
	}
	return l.accept()
}

func (l *stubListener) Close() error { return nil }

func (l *stubListener) Addr() net.Addr {
	if l == nil {
		return nil
	}
	return l.addr
}

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

func TestSilentPeerHTTPServedBeforeHeaderTimeout(t *testing.T) {
	headerTO := time.Second
	spec := loadSpec(t)
	spec.Proxy.Admission.HeaderTimeout = headerTO
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	px := startProxy(t, Options{Spec: spec})
	silent, err := net.DialTimeout("tcp", px.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()

	tr := &http.Transport{
		Proxy:                 http.ProxyURL(mustURL(t, "http://"+px.Addr().String())),
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: headerTO,
	}
	defer tr.CloseIdleConnections()
	start := time.Now()
	req := mustRequest(t, http.MethodGet, originURL+"/hello")
	resp, err := tr.RoundTrip(req)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("second client blocked by silent peer: %v (waited %v)", err, elapsed)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if elapsed >= headerTO/2 {
		t.Fatalf("second peer waited %v; HeaderTimeout=%v (Accept must not peek)", elapsed, headerTO)
	}
}

func TestSOCKSCloseWhenAcceptFlagsOff(t *testing.T) {
	spec := loadSpec(t)
	spec.Listeners.Proxy.AcceptSOCKS5 = false
	spec.Listeners.Proxy.AcceptSOCKS4 = false
	px := startProxy(t, Options{Spec: spec})
	for _, first := range []byte{0x04, 0x05} {
		c, err := net.DialTimeout("tcp", px.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte{first, 0x01, 0x00}); err != nil {
			_ = c.Close()
			t.Fatal(err)
		}
		buf := make([]byte, 16)
		n, err := c.Read(buf)
		_ = c.Close()
		if n != 0 && err == nil {
			t.Fatalf("first=0x%02x got %q; want close", first, buf[:n])
		}
		if err == nil {
			t.Fatalf("first=0x%02x: expected close", first)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("socks") < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("socks") < 2 {
		t.Fatalf("socks rejects=%d want >=2", px.Metrics().Rejected("socks"))
	}
}

func TestSOCKSGreetingWhenAcceptFlagsOn(t *testing.T) {
	spec := loadSpec(t)
	spec.Listeners.Proxy.AcceptSOCKS5 = true
	spec.Listeners.Proxy.AcceptSOCKS4 = true
	px := startProxy(t, Options{Spec: spec})
	c, err := net.DialTimeout("tcp", px.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		t.Fatalf("SOCKS greeting %x; want 05 00 (peeked 0x05 replayed)", buf)
	}
}

func TestShutdownUnblocksSilentPeer(t *testing.T) {
	px := startProxy(t, Options{})
	silent, err := net.DialTimeout("tcp", px.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- px.Shutdown(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown blocked on silent peer")
	}
}

func TestAcceptLoopRetriesTemporaryThenStops(t *testing.T) {
	s, err := New(Options{Address: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	var n atomic.Int32
	retried := make(chan struct{})
	ln := &stubListener{
		addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		accept: func() (net.Conn, error) {
			i := n.Add(1)
			if i == 1 {
				return nil, tempNetErr{}
			}
			if i == 2 {
				close(retried)
			}
			return nil, net.ErrClosed
		},
	}
	s.accepting.Store(true)
	s.acceptWG.Add(1)
	go s.acceptLoop(ln, kindProxy)
	select {
	case <-retried:
	case <-time.After(time.Second):
		t.Fatal("Accept did not retry after temporary error")
	}
	s.acceptWG.Wait()
	if s.Accepting() {
		t.Fatal("Accepting still true after fatal Accept")
	}
}

func TestPeekReplayReplaysByte(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	go func() { _, _ = b.Write([]byte("GET /")) }()
	pc, peek, err := peekReplay(a, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(peek) != 1 || peek[0] != 'G' {
		t.Fatalf("peek %q", peek)
	}
	buf := make([]byte, 5)
	n, err := io.ReadFull(pc, buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 || string(buf) != "GET /" {
		t.Fatalf("replayed %q", buf[:n])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

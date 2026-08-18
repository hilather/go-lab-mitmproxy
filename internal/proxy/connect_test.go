package proxy

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
)

func TestCONNECTNoPort(t *testing.T) {
	px := startProxy(t, Options{})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "connect-no-port.txt"), nil)
}

func TestCONNECTTwoGETs(t *testing.T) {
	hits := map[string]int{}
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits[r.URL.Path]++
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	px := startProxy(t, Options{})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteRequest("CONNECT "+origin+" HTTP/1.1", "Host: "+origin); err != nil {
		t.Fatal(err)
	}
	st, err := c.ReadLine()
	if err != nil {
		t.Fatal(err)
	}
	if st != "HTTP/1.1 200 Connection Established" {
		t.Fatalf("status %q", st)
	}
	if blank, err := c.ReadLine(); err != nil || blank != "" {
		t.Fatalf("blank %q err=%v", blank, err)
	}
	for _, path := range []string{"/a", "/b"} {
		if err := c.WriteRequest("GET "+path+" HTTP/1.1", "Host: "+origin); err != nil {
			t.Fatal(err)
		}
		resp, err := c.ReadResponse()
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != path {
			t.Fatalf("%s: status %d body %q", path, resp.StatusCode, body)
		}
	}
	if hits["/a"] != 1 || hits["/b"] != 1 {
		t.Fatalf("hits %#v", hits)
	}
}

func TestCONNECTHijackClientHelloNot400(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()

	px := startProxy(t, Options{})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	host := ln.Addr().String()
	if err := c.WriteRequest("CONNECT "+host+" HTTP/1.1", "Host: "+host); err != nil {
		t.Fatal(err)
	}
	st, err := c.ReadLine()
	if err != nil {
		t.Fatal(err)
	}
	if st != "HTTP/1.1 200 Connection Established" {
		t.Fatalf("status %q — missed Hijack?", st)
	}
	if blank, err := c.ReadLine(); err != nil || blank != "" {
		t.Fatalf("blank %q err=%v", blank, err)
	}
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 'H', 'I', 'J', 'A', 'K'}
	if err := c.WriteRaw(hello); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-got:
		if len(b) == 0 || b[0] != 0x16 {
			t.Fatalf("origin got %q; ClientHello was parsed as HTTP", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("origin did not receive tunneled bytes")
	}
}

func TestCONNECTHijackTranscript(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	}()
	px := startProxy(t, Options{})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "connect-hijack.txt"), map[string]string{
		"HOST": ln.Addr().String(),
	})
}

func TestWebSocketUpgrade(t *testing.T) {
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "no upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", 500)
			return
		}
		c, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = bufrw.Flush()
		// echo one frame-ish blob
		buf := make([]byte, 64)
		n, _ := bufrw.Read(buf)
		_, _ = bufrw.Write(buf[:n])
		_ = bufrw.Flush()
	}))
	px := startProxy(t, Options{})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteRequest(
		"GET http://"+origin+"/ws HTTP/1.1",
		"Host: "+origin,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
	); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if err := c.WriteRaw([]byte("ping-ws")); err != nil {
		t.Fatal(err)
	}
	echo, err := c.ReadN(7)
	if err != nil {
		t.Fatal(err)
	}
	if string(echo) != "ping-ws" {
		t.Fatalf("echo %q", echo)
	}
}

func TestWebSocketTranscript(t *testing.T) {
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", 500)
			return
		}
		c, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = bufrw.Flush()
		_, _ = io.Copy(io.Discard, bufrw)
	}))
	px := startProxy(t, Options{})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "upgrade-websocket.txt"), map[string]string{
		"HOST": origin,
	})
}

func TestCONNECTUsesRequestTargetNotHost(t *testing.T) {
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	px := startProxy(t, Options{})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteRequest("CONNECT "+origin+" HTTP/1.1", "Host: 169.254.169.254:80"); err != nil {
		t.Fatal(err)
	}
	st, err := c.ReadLine()
	if err != nil {
		t.Fatal(err)
	}
	if st != "HTTP/1.1 200 Connection Established" {
		t.Fatalf("used Host header instead of request-target: %q", st)
	}
}

func TestCONNECTSessionTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.Copy(io.Discard, c)
	}()
	spec := loadSpec(t)
	spec.Proxy.Admission.SessionTimeout = 200 * time.Millisecond
	spec.Proxy.Admission.IdleTimeout = 200 * time.Millisecond
	px := startProxy(t, Options{Spec: spec})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	host := ln.Addr().String()
	if err := c.WriteRequest("CONNECT "+host+" HTTP/1.1", "Host: "+host); err != nil {
		t.Fatal(err)
	}
	st, err := c.ReadLine()
	if err != nil {
		t.Fatal(err)
	}
	if st != "HTTP/1.1 200 Connection Established" {
		t.Fatalf("status %q", st)
	}
	if blank, err := c.ReadLine(); err != nil || blank != "" {
		t.Fatalf("blank %q err=%v", blank, err)
	}
	time.Sleep(400 * time.Millisecond)
	_ = c.Conn.SetDeadline(time.Now().Add(time.Second))
	_, err = c.Conn.Write([]byte("still-here"))
	if err == nil {
		buf := make([]byte, 8)
		_, err = c.Conn.Read(buf)
	}
	if err == nil {
		t.Fatal("sessionTimeout did not close hijacked tunnel")
	}
}

func TestInterceptTrueStillTunnels(t *testing.T) {
	// Non-listed ports stay a raw tunnel even with intercept:true (D20).
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "plain")
	}))
	spec := loadSpec(t)
	spec.TLS.Intercept = true
	spec.TLS.Ports = []int{443}
	px := startProxy(t, Options{Spec: spec})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteRequest("CONNECT "+origin+" HTTP/1.1", "Host: "+origin); err != nil {
		t.Fatal(err)
	}
	st, err := c.ReadLine()
	if err != nil {
		t.Fatal(err)
	}
	if st != "HTTP/1.1 200 Connection Established" {
		t.Fatalf("intercept:true CONNECT %q", st)
	}
}

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
	"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm"
	"github.com/hilather/go-lab-mitmproxy/internal/wsx"
)

func interceptSpec(t *testing.T, originPort int, extraCA string) model.Spec {
	t.Helper()
	spec := loadSpec(t)
	spec.TLS.Intercept = true
	spec.TLS.Ports = []int{originPort}
	if extraCA != "" {
		spec.TLS.Upstream.ExtraCAFiles = []string{extraCA}
	}
	return spec
}

func appLabResolver() mapResolver {
	return mapResolver{"app.lab": {net.ParseIP("127.0.0.1")}}
}

func httpsViaProxy(t *testing.T, proxyAddr, originPort, path string, roots *x509.CertPool) (*http.Response, error) {
	t.Helper()
	tr := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
		TLSClientConfig: &tls.Config{
			ServerName: "app.lab",
			RootCAs:    roots,
			NextProtos: []string{tlsmitm.ALPN},
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	t.Cleanup(tr.CloseIdleConnections)
	req, err := http.NewRequest(http.MethodGet, "https://app.lab:"+originPort+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tr.RoundTrip(req)
}

func TestInterceptTrustedClientSucceeds(t *testing.T) {
	var hits atomic.Int32
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/hello" {
			t.Errorf("path %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, "secret-body")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	auth := px.Authority()
	if auth == nil {
		t.Fatal("missing lab CA")
	}
	resp, err := httpsViaProxy(t, px.Addr().String(), strconv.Itoa(port), "/hello", auth.CertPool())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "secret-body" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if hits.Load() != 1 {
		t.Fatalf("origin hits %d", hits.Load())
	}
	if px.Metrics().TLSIntercepts(tlsmitm.ResultOK) < 1 {
		t.Fatal("missing tls intercept ok")
	}
	found := false
	for _, f := range sink.Last() {
		if f.Intercepted && f.Scheme == "https" && f.Method == http.MethodGet && strings.Contains(f.URL, "/hello") {
			found = true
			if f.TLS == nil || f.TLS.ALPN != tlsmitm.ALPN {
				t.Fatalf("TLSInfo %+v", f.TLS)
			}
			if !f.TLS.UpstreamVerified {
				t.Fatal("expected upstream verified")
			}
		}
	}
	if !found {
		t.Fatalf("no intercepted flow: %+v", sink.Last())
	}
}

func TestInterceptUntrustedClientFails(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin should not be reached")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	_, err := httpsViaProxy(t, px.Addr().String(), strconv.Itoa(port), "/nope", x509.NewCertPool())
	if err == nil {
		t.Fatal("untrusted client succeeded")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range sink.Last() {
			if f.Error == tlsmitm.ResultTLSHandshake {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("want Error=tls_handshake, got %+v", sink.Last())
}

func TestCONNECTPort80InterceptTunnels(t *testing.T) {
	var hits atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "plain-80")
	})
	origin := ""
	if ln, err := net.Listen("tcp", "127.0.0.1:80"); err == nil {
		t.Cleanup(func() { _ = ln.Close() })
		proto := http1Only()
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, Protocols: proto,
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { _ = srv.Close() })
		origin = ln.Addr().String()
	} else {
		origin, _ = startOrigin(t, h)
	}
	sink := NewNull()
	spec := loadSpec(t)
	spec.TLS.Intercept = true
	spec.TLS.Ports = []int{443}
	px := startProxy(t, Options{Spec: spec, Sink: sink})
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
	if err := c.WriteRequest("GET /plain HTTP/1.1", "Host: "+origin); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "plain-80" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
	for _, f := range sink.Last() {
		if f.Protocol == model.FlowProtocolConnect && f.Intercepted {
			t.Fatalf("port 80 should not intercept: %+v", f)
		}
	}
}

func TestCONNECT443PlaintextNoBlindTunnel(t *testing.T) {
	var hits atomic.Int32
	var first []byte
	got := make(chan []byte, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		first = append([]byte(nil), buf[:n]...)
		got <- first
		hits.Add(1)
	}()
	_, port := hostPort(t, ln.Addr().String())
	sink := NewNull()
	spec := loadSpec(t)
	spec.TLS.Intercept = true
	spec.TLS.Ports = []int{port}
	px := startProxy(t, Options{Spec: spec, Sink: sink})
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
	// Plaintext GET after CONNECT: client handshake fails. Must not tunnel.
	if err := c.WriteRequest("GET /secret HTTP/1.1", "Host: "+host); err != nil {
		t.Fatal(err)
	}
	_ = c.Conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.ReadLine()

	deadline := time.Now().Add(2 * time.Second)
	var sawHandshake bool
	for time.Now().Before(deadline) {
		for _, f := range sink.Last() {
			if f.Error == tlsmitm.ResultTLSHandshake {
				sawHandshake = true
			}
		}
		if sawHandshake {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sawHandshake {
		t.Fatalf("want Error=tls_handshake, got %+v", sink.Last())
	}
	select {
	case b := <-got:
		if strings.Contains(string(b), "/secret") || strings.HasPrefix(string(b), "GET ") {
			t.Fatalf("blind-tunneled client bytes %q", b)
		}
	case <-time.After(500 * time.Millisecond):
		// origin never saw a tunnel — also correct (we never handshook upstream)
	}
	if px.Metrics().TLSIntercepts(tlsmitm.ResultTLSHandshake) < 1 {
		t.Fatal("missing tls_handshake metric")
	}
}

func TestInterceptTwoInnerGETs(t *testing.T) {
	hits := map[string]int{}
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits[r.URL.Path]++
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	tr := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: px.Addr().String()}),
		TLSClientConfig: &tls.Config{
			ServerName: "app.lab",
			RootCAs:    px.Authority().CertPool(),
			NextProtos: []string{tlsmitm.ALPN},
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	defer tr.CloseIdleConnections()
	for _, path := range []string{"/a", "/b"} {
		req, err := http.NewRequest(http.MethodGet, "https://app.lab:"+strconv.Itoa(port)+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := tr.RoundTrip(req)
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
	deadline := time.Now().Add(time.Second)
	var inner int
	for {
		inner = 0
		for _, f := range sink.Last() {
			if f.Intercepted && f.Protocol == model.FlowProtocolHTTP11 {
				inner++
			}
		}
		if inner >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("want 2 inner flows, got %+v", sink.Last())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestHandshakeNextProtosFromSpec(t *testing.T) {
	spec := model.Spec{}
	got := handshakeClientNextProtos(spec)
	if len(got) != 1 || got[0] != tlsmitm.ALPN {
		t.Fatalf("flag off client %v", got)
	}
	if orig := handshakeOriginNextProtos(); len(orig) != 1 || orig[0] != tlsmitm.ALPN {
		t.Fatalf("flag off origin %v", orig)
	}
	spec.Protocols.HTTP2.Enabled = true
	got = handshakeClientNextProtos(spec)
	if len(got) != 2 || got[0] != "h2" || got[1] != tlsmitm.ALPN {
		t.Fatalf("flag on client %v", got)
	}
	if orig := handshakeOriginNextProtos(); len(orig) != 1 || orig[0] != tlsmitm.ALPN {
		t.Fatalf("flag on origin stays http/1.1 (h2 inner transcodes) %v", orig)
	}
}

func TestInterceptInnerHTTP2Preface(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin should not be reached")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	target := net.JoinHostPort("app.lab", strconv.Itoa(port))
	if err := c.WriteRequest("CONNECT "+target+" HTTP/1.1", "Host: "+target); err != nil {
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
		t.Fatalf("blank %q", blank)
	}
	tlsConn := tls.Client(c.Conn, &tls.Config{
		ServerName: "app.lab",
		RootCAs:    px.Authority().CertPool(),
		NextProtos: []string{tlsmitm.ALPN},
		MinVersion: tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsConn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if px.Metrics().TLSIntercepts(tlsmitm.ResultHTTP2Inner) >= 1 {
			return
		}
		for _, f := range sink.Last() {
			if f.Error == tlsmitm.ResultHTTP2Inner {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("want http2_inner, got metrics=%d flows=%+v", px.Metrics().TLSIntercepts(tlsmitm.ResultHTTP2Inner), sink.Last())
}

func TestInterceptHTTP2EnabledStillInnerPRI(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin should not be reached")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	spec.Protocols.HTTP2.Enabled = true
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	target := net.JoinHostPort("app.lab", strconv.Itoa(port))
	if err := c.WriteRequest("CONNECT "+target+" HTTP/1.1", "Host: "+target); err != nil {
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
		t.Fatalf("blank %q", blank)
	}
	tlsConn := tls.Client(c.Conn, &tls.Config{
		ServerName: "app.lab",
		RootCAs:    px.Authority().CertPool(),
		NextProtos: []string{tlsmitm.ALPN},
		MinVersion: tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != tlsmitm.ALPN {
		t.Fatalf("ALPN=%q (want http/1.1; h2 is a separate inner path)", tlsConn.ConnectionState().NegotiatedProtocol)
	}
	if _, err := tlsConn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if px.Metrics().TLSIntercepts(tlsmitm.ResultHTTP2Inner) >= 1 {
			return
		}
		for _, f := range sink.Last() {
			if f.Error == tlsmitm.ResultHTTP2Inner {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("want http2_inner with flag on, got metrics=%d flows=%+v", px.Metrics().TLSIntercepts(tlsmitm.ResultHTTP2Inner), sink.Last())
}

func TestInterceptALPNHTTP11(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	_, port := hostPort(t, origin)
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	target := net.JoinHostPort("app.lab", strconv.Itoa(port))
	if err := c.WriteRequest("CONNECT "+target+" HTTP/1.1", "Host: "+target); err != nil {
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
		t.Fatalf("blank %q", blank)
	}
	tlsConn := tls.Client(c.Conn, &tls.Config{
		ServerName: "app.lab",
		RootCAs:    px.Authority().CertPool(),
		NextProtos: []string{"h2", tlsmitm.ALPN},
		MinVersion: tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != tlsmitm.ALPN {
		t.Fatalf("ALPN=%q", tlsConn.ConnectionState().NegotiatedProtocol)
	}
}

func TestInterceptFilesMode(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "files")
	}))
	_, port := hostPort(t, origin)
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	spec.TLS.CA.Mode = model.CAModeFiles
	spec.TLS.CA.CertFile = testdataTLS(t, "ca.pem")
	spec.TLS.CA.KeyFile = testdataTLS(t, "ca-key.pem")
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	roots := pemPool(t, testdataTLS(t, "ca.pem"))
	resp, err := httpsViaProxy(t, px.Addr().String(), strconv.Itoa(port), "/f", roots)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "files" {
		t.Fatalf("body %q", body)
	}
}

func TestInterceptUpstreamVerifyFail(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not fetch")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptSpec(t, port, "") // no extra CA; origin is unknown
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	_, err := httpsViaProxy(t, px.Addr().String(), strconv.Itoa(port), "/x", px.Authority().CertPool())
	if err == nil {
		t.Fatal("expected upstream verify failure to close the session")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range sink.Last() {
			if f.Error == tlsmitm.ResultUpstreamVerifyFail || f.Error == tlsmitm.ResultUpstreamTLS {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("want upstream_tls/verify_fail, got %+v", sink.Last())
}

func TestInterceptFalseRemainsTunnel(t *testing.T) {
	var hits atomic.Int32
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "tunneled")
	}))
	_, port := hostPort(t, origin)
	spec := loadSpec(t)
	spec.TLS.Intercept = false
	spec.TLS.Ports = []int{port}
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
		t.Fatalf("status %q", st)
	}
	if blank, err := c.ReadLine(); err != nil || blank != "" {
		t.Fatalf("blank %q", blank)
	}
	tlsConn := tls.Client(c.Conn, &tls.Config{
		ServerName: "app.lab",
		RootCAs:    pemPool(t, testdataTLS(t, "origin-ca.pem")),
		NextProtos: []string{tlsmitm.ALPN},
		MinVersion: tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://app.lab/", nil)
	if err := req.Write(tlsConn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "tunneled" || hits.Load() != 1 {
		t.Fatalf("body %q hits %d", body, hits.Load())
	}
}

func TestInterceptWebSocketUpgrade(t *testing.T) {
	var sawUpgrade atomic.Bool
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "no upgrade", http.StatusBadRequest)
			return
		}
		sawUpgrade.Store(true)
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		c, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = bufrw.Flush()
		buf := make([]byte, 64)
		n, _ := bufrw.Read(buf)
		_, _ = bufrw.Write(buf[:n])
		_ = bufrw.Flush()
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	target := net.JoinHostPort("app.lab", strconv.Itoa(port))
	if err := c.WriteRequest("CONNECT "+target+" HTTP/1.1", "Host: "+target); err != nil {
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
		t.Fatalf("blank %q", blank)
	}
	tlsConn := tls.Client(c.Conn, &tls.Config{
		ServerName: "app.lab",
		RootCAs:    px.Authority().CertPool(),
		NextProtos: []string{tlsmitm.ALPN},
		MinVersion: tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://app.lab/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if err := req.Write(tlsConn); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, err := tlsConn.Write([]byte("ping-ws")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 7)
	if _, err := io.ReadFull(br, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "ping-ws" {
		t.Fatalf("echo %q", echo)
	}
	if !sawUpgrade.Load() {
		t.Fatal("origin did not see websocket upgrade")
	}
	found := false
	for _, f := range sink.Last() {
		if f.Protocol == model.FlowProtocolWebSocket && f.Intercepted {
			found = true
		}
	}
	if !found {
		t.Fatalf("want intercepted websocket flow, got %+v", sink.Last())
	}
}

func TestInterceptWebSocketInspectFrames(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		c, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = bufrw.Flush()
		for {
			fr, err := wsx.ReadFrame(bufrw, 0)
			if err != nil {
				return
			}
			fr.Masked = false
			fr.MaskKey = [4]byte{}
			if err := wsx.WriteFrame(bufrw, fr); err != nil {
				return
			}
			_ = bufrw.Flush()
			if fr.Opcode == wsx.OpcodeClose {
				return
			}
		}
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	spec.Protocols.WebSocket.InspectFrames = true
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	target := net.JoinHostPort("app.lab", strconv.Itoa(port))
	if err := c.WriteRequest("CONNECT "+target+" HTTP/1.1", "Host: "+target); err != nil {
		t.Fatal(err)
	}
	if st, err := c.ReadLine(); err != nil || st != "HTTP/1.1 200 Connection Established" {
		t.Fatalf("status %v %v", st, err)
	}
	if blank, err := c.ReadLine(); err != nil || blank != "" {
		t.Fatalf("blank %q", blank)
	}
	tlsConn := tls.Client(c.Conn, &tls.Config{
		ServerName: "app.lab",
		RootCAs:    px.Authority().CertPool(),
		NextProtos: []string{tlsmitm.ALPN},
		MinVersion: tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://app.lab/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if err := req.Write(tlsConn); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	fr := wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("inner")}
	if err := wsx.WriteFrame(tlsConn, fr); err != nil {
		t.Fatal(err)
	}
	got, err := wsx.ReadFrame(br, 0)
	if err != nil || string(got.Payload) != "inner" {
		t.Fatalf("echo %v %+v", err, got)
	}
	if err := wsx.WriteFrame(tlsConn, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000}); err != nil {
		t.Fatal(err)
	}
	_, _ = wsx.ReadFrame(br, 0)
	_ = tlsConn.Close()
	f := waitWSFlow(t, sink)
	if !f.Intercepted || f.WebSocket == nil || f.WebSocket.FrameCount < 1 {
		t.Fatalf("want intercepted frames, got %+v", f)
	}
}

func TestInterceptInnerRoundTripFails502(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		c, _, err := hj.Hijack()
		if err != nil {
			return
		}
		_ = c.Close()
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	tr := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: px.Addr().String()}),
		TLSClientConfig: &tls.Config{
			ServerName: "app.lab",
			RootCAs:    px.Authority().CertPool(),
			NextProtos: []string{tlsmitm.ALPN},
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab:"+strconv.Itoa(port)+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	resp, err := tr.RoundTrip(req)
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("inner failure hung %s err=%v", d, err)
	}
	if err != nil {
		t.Fatalf("client err %v (want 502)", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func pemPool(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(pemBytes); block == nil {
		t.Fatal("no pem")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("append %s", path)
	}
	return pool
}

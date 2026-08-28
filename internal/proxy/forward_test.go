package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
)

func TestAbsoluteFormGET(t *testing.T) {
	var sawHost, sawURI string
	origin, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHost = r.Host
		sawURI = r.URL.RequestURI()
		if r.URL.Scheme != "" && r.URL.Host != "" && strings.HasPrefix(r.RequestURI, "http://") {
			t.Errorf("origin saw absolute-form %q", r.RequestURI)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	_ = origin
	px := startProxy(t, Options{})
	via := throughProxy(t, px.Addr().String(), originURL+"/hello")
	if via != "ok" {
		t.Fatalf("body %q", via)
	}
	u, _ := url.Parse(originURL)
	if sawHost != u.Host {
		t.Fatalf("origin Host=%q want %q", sawHost, u.Host)
	}
	if sawURI != "/hello" {
		t.Fatalf("origin URI=%q", sawURI)
	}
}

func TestAbsoluteFormPOST(t *testing.T) {
	var got string
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "saved")
	}))
	px := startProxy(t, Options{})
	tr := &http.Transport{
		Proxy:             http.ProxyURL(mustURL(t, "http://"+px.Addr().String())),
		ForceAttemptHTTP2: false,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodPost, originURL+"/p", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got != "body" {
		t.Fatalf("origin body %q", got)
	}
}

func TestHopByHopStripped(t *testing.T) {
	var hop http.Header
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hop = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	px := startProxy(t, Options{})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteRequest(
		"GET "+originURL+"/h HTTP/1.1",
		"Host: "+mustURL(t, originURL).Host,
		"Proxy-Connection: keep-alive",
		"Connection: Keep-Alive",
		"Keep-Alive: timeout=5",
		"Proxy-Authorization: Basic x",
	); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if hop.Get("Proxy-Connection") != "" || hop.Get("Keep-Alive") != "" || hop.Get("Proxy-Authorization") != "" {
		t.Fatalf("hop-by-hop leaked: %v", hop)
	}
}

func TestExpectStripped(t *testing.T) {
	var expect string
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expect = r.Header.Get("Expect")
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b)
	}))
	px := startProxy(t, Options{})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	msg := "POST " + originURL + "/e HTTP/1.1\r\nHost: " + mustURL(t, originURL).Host + "\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\nping"
	if err := c.WriteRaw([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if expect != "" {
		t.Fatalf("origin saw Expect=%q", expect)
	}
	if resp.StatusCode == http.StatusContinue {
		t.Fatal("client saw 100 Continue as the final status")
	}
}

func TestExpectChunked(t *testing.T) {
	var got, expect string
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expect = r.Header.Get("Expect")
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		_, _ = io.WriteString(w, "ok")
	}))
	px := startProxy(t, Options{})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	host := mustURL(t, originURL).Host
	msg := "POST http://" + host + "/e HTTP/1.1\r\nHost: " + host + "\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nping\r\n0\r\n\r\n"
	if err := c.WriteRaw([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if expect != "" {
		t.Fatalf("origin saw Expect=%q", expect)
	}
	if got != "ping" {
		t.Fatalf("origin body %q", got)
	}
	if resp.StatusCode == http.StatusContinue {
		t.Fatal("client saw 100 Continue")
	}
}

func TestAbsoluteFormIPv6(t *testing.T) {
	var sawHost string
	_, originURL := startOriginOn(t, "tcp", "[::1]:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHost = r.Host
		_, _ = io.WriteString(w, "v6")
	}))
	px := startProxy(t, Options{})
	via := throughProxy(t, px.Addr().String(), originURL+"/hello")
	if via != "v6" {
		t.Fatalf("body %q", via)
	}
	want := mustURL(t, originURL).Host
	if sawHost != want {
		t.Fatalf("origin Host=%q want %q", sawHost, want)
	}
	if !strings.HasPrefix(sawHost, "[::1]") {
		t.Fatalf("IPv6 Host not bracketed: %q", sawHost)
	}
}

func TestNewZeroSpecDeniesIMDS(t *testing.T) {
	rec := &recordingDial{}
	s, err := New(Options{
		Address:     "127.0.0.1:0",
		Spec:        loadSpec(t),
		DialContext: rec.wrap(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	c, err := proxytest.Dial(s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteRequest("GET http://169.254.169.254/ HTTP/1.1", "Host: 169.254.169.254"); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := rec.Addrs(); len(got) != 0 {
		t.Fatalf("dialed %v", got)
	}
}

func TestAbsoluteFormDisabledBeforeDNS(t *testing.T) {
	res := &countingResolver{inner: mapResolver{"app.lab": {net.ParseIP("127.0.0.1")}}}
	rec := &recordingDial{}
	sink := NewNull()
	spec := loadSpec(t)
	spec.Protocols.AbsoluteForm.Enabled = false
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: res, DialContext: rec.wrap(nil)})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteRequest("GET http://app.lab/hello HTTP/1.1", "Host: app.lab"); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if res.n.Load() != 0 {
		t.Fatalf("DNS lookups=%d", res.n.Load())
	}
	if len(rec.Addrs()) != 0 {
		t.Fatalf("dialed %v", rec.Addrs())
	}
	if px.Metrics().Rejected("absolute_form") < 1 {
		t.Fatal("expected absolute_form reject")
	}
	found := false
	for _, f := range sink.Last() {
		if f.Protocol == model.FlowProtocolHTTP11 && f.Error == "forbidden" && f.Status == http.StatusForbidden {
			found = true
		}
	}
	if !found {
		t.Fatalf("want absolute-form forbidden flow, got %+v", sink.Last())
	}
}

func TestHTTPProxyEnvIgnored(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")

	ln, err := net.Listen("tcp", "127.0.0.1:1")
	if err == nil {
		_ = ln.Close()
	}

	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "direct")
	}))
	px := startProxy(t, Options{})
	got := throughProxy(t, px.Addr().String(), originURL+"/")
	if got != "direct" {
		t.Fatalf("body %q (HTTP_PROXY was honored?)", got)
	}
}

func TestAbsoluteHTTPSTranscript(t *testing.T) {
	px := startProxy(t, Options{})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "absolute-https.txt"), nil)
	if px.Metrics().Rejected("absolute_https") < 1 {
		t.Fatal("expected absolute_https reject")
	}
}

func TestOriginFormTranscript(t *testing.T) {
	px := startProxy(t, Options{})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "origin-form.txt"), nil)
}

func TestAbsoluteGetTranscript(t *testing.T) {
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	px := startProxy(t, Options{})
	host := mustURL(t, originURL).Host
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "absolute-get.txt"), map[string]string{
		"HOST": host,
	})
}

func TestNameIMDSDoesNotDial(t *testing.T) {
	rec := &recordingDial{}
	px := startProxy(t, Options{
		Resolver:    mapResolver{"metadata.google.internal": {net.ParseIP("169.254.169.254")}},
		DialContext: rec.wrap(nil),
	})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "name-imds.txt"), nil)
	if got := rec.Addrs(); len(got) != 0 {
		t.Fatalf("dialed %v", got)
	}
	if px.Metrics().Rejected("target_denied") < 1 {
		t.Fatal("expected target_denied")
	}
}

func TestNameLinkLocalDoesNotDial(t *testing.T) {
	rec := &recordingDial{}
	px := startProxy(t, Options{
		Resolver:    mapResolver{"linklocal.test": {net.ParseIP("fe80::1")}},
		DialContext: rec.wrap(nil),
	})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "name-link-local.txt"), nil)
	if got := rec.Addrs(); len(got) != 0 {
		t.Fatalf("dialed %v", got)
	}
}

func throughProxy(t *testing.T, proxyAddr, target string) string {
	t.Helper()
	tr := &http.Transport{
		Proxy:             http.ProxyURL(mustURL(t, "http://"+proxyAddr)),
		ForceAttemptHTTP2: false,
	}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(mustRequest(t, http.MethodGet, target))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %q", resp.StatusCode, b)
	}
	return string(b)
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mustRequest(t *testing.T, method, raw string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

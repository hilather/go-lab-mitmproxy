package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/compiler"
	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func httpAuthBasic() string {
	return base64.StdEncoding.EncodeToString([]byte("labuser:labpass12"))
}

func httpAuthSpec(t *testing.T, enabled bool) model.Spec {
	t.Helper()
	spec := loadSpec(t)
	root := moduleRoot(t)
	spec.Proxy.HTTPAuth = model.HTTPAuthSpec{
		Enabled: enabled,
		Realm:   config.DefaultHTTPAuthRealm,
		Users: []model.UserPassUserSpec{{
			ID:           "lab-proxy",
			UsernameFile: filepath.Join(root, "testdata", "config", "valid", "socks-username"),
			PasswordFile: filepath.Join(root, "testdata", "config", "valid", "socks-password"),
		}},
	}
	return spec
}

func startHTTPAuthProxy(t *testing.T, opts Options) *Server {
	t.Helper()
	if opts.Spec.Listeners.Proxy.Address == "" && !opts.Spec.Proxy.HTTPAuth.Enabled && len(opts.Spec.Proxy.HTTPAuth.Users) == 0 {
		opts.Spec = httpAuthSpec(t, true)
	}
	st := &model.State{
		APIVersion: model.APIVersionV1Alpha1,
		Kind:       model.KindLabMITM,
		Metadata:   model.Metadata{Name: "t"},
		Spec:       opts.Spec,
	}
	snap, err := compiler.Compile(t.Context(), st, compiler.CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	snaps := snapshot.NewStore()
	snaps.InstallBootstrap(snap)
	opts.Spec = snap.Canonical.Spec
	opts.Snapshots = snaps
	if opts.Authority == nil {
		opts.Authority = snap.CA
	}
	return startProxy(t, opts)
}

func waitReject(t *testing.T, px *Server, reason string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected(reason) < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected(reason) < 1 {
		t.Fatalf("expected reject reason=%s", reason)
	}
}

func TestHTTPAuthAbsolute407Transcript(t *testing.T) {
	rec := &recordingDial{}
	origin, _ := startOrigin(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("origin must not be reached")
	}))
	px := startHTTPAuthProxy(t, Options{DialContext: rec.wrap(nil)})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "http-auth-absolute-407.txt"), map[string]string{
		"HOST": origin,
	})
	if len(rec.Addrs()) != 0 {
		t.Fatalf("407 dialed %v", rec.Addrs())
	}
	waitReject(t, px, "proxy_auth")
}

func TestHTTPAuthAbsoluteOKTranscript(t *testing.T) {
	var sawAuth string
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Proxy-Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	sink := NewNull()
	px := startHTTPAuthProxy(t, Options{Sink: sink})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "http-auth-absolute-ok.txt"), map[string]string{
		"HOST":  origin,
		"BASIC": httpAuthBasic(),
	})
	if sawAuth != "" {
		t.Fatalf("origin saw Proxy-Authorization %q", sawAuth)
	}
	assertFlowsHideProxyAuth(t, sink)
}

func TestHTTPAuthCONNECT407Transcript(t *testing.T) {
	rec := &recordingDial{}
	origin, _ := startOrigin(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("origin must not be reached")
	}))
	px := startHTTPAuthProxy(t, Options{DialContext: rec.wrap(nil)})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "http-auth-connect-407.txt"), map[string]string{
		"HOST": origin,
	})
	if len(rec.Addrs()) != 0 {
		t.Fatalf("407 CONNECT dialed %v", rec.Addrs())
	}
	waitReject(t, px, "proxy_auth")
}

func TestHTTPAuthCONNECTRetryTranscript(t *testing.T) {
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
		_ = c.Close()
	}()
	px := startHTTPAuthProxy(t, Options{})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "http-auth-connect-retry.txt"), map[string]string{
		"HOST":  ln.Addr().String(),
		"BASIC": httpAuthBasic(),
	})
}

func TestHTTPAuthOffTranscript(t *testing.T) {
	var sawAuth string
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Proxy-Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	px := startHTTPAuthProxy(t, Options{Spec: httpAuthSpec(t, false)})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "http-auth-off.txt"), map[string]string{
		"HOST":  origin,
		"BASIC": httpAuthBasic(),
	})
	if sawAuth != "" {
		t.Fatalf("origin saw Proxy-Authorization %q", sawAuth)
	}
}

func TestHTTPAuthWrongPasswordNoDial(t *testing.T) {
	rec := &recordingDial{}
	px := startHTTPAuthProxy(t, Options{DialContext: rec.wrap(nil)})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	bad := base64.StdEncoding.EncodeToString([]byte("labuser:wrong"))
	if err := c.WriteRequest("GET http://127.0.0.1:9/x HTTP/1.1", "Host: 127.0.0.1:9", "Proxy-Authorization: Basic "+bad); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(rec.Addrs()) != 0 {
		t.Fatalf("dialed %v", rec.Addrs())
	}
}

func TestHTTPAuthNonBasicAndGarbage407(t *testing.T) {
	rec := &recordingDial{}
	px := startHTTPAuthProxy(t, Options{DialContext: rec.wrap(nil)})
	for _, hdr := range []string{"Digest realm=x", "Basic %%%%", "Basic"} {
		c, err := proxytest.Dial(px.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if err := c.WriteRequest("GET http://127.0.0.1:9/x HTTP/1.1", "Host: 127.0.0.1:9", "Proxy-Authorization: "+hdr); err != nil {
			_ = c.Close()
			t.Fatal(err)
		}
		resp, err := c.ReadResponse()
		if err != nil {
			_ = c.Close()
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		_ = c.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("%q status %d", hdr, resp.StatusCode)
		}
	}
	if len(rec.Addrs()) != 0 {
		t.Fatalf("dialed %v", rec.Addrs())
	}
}

func TestHTTPAuthCONNECTMissingPortStill400(t *testing.T) {
	px := startHTTPAuthProxy(t, Options{})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "connect-no-port.txt"), nil)
	if px.Metrics().Rejected("proxy_auth") != 0 {
		t.Fatal("missing-port CONNECT must not consult auth")
	}
}

func TestHTTPAuthCONNECTDisabledStill403(t *testing.T) {
	spec := httpAuthSpec(t, true)
	spec.Protocols.Connect.Enabled = false
	px := startHTTPAuthProxy(t, Options{Spec: spec})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteRequest("CONNECT 127.0.0.1:9 HTTP/1.1", "Host: 127.0.0.1:9"); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d want 403", resp.StatusCode)
	}
	waitReject(t, px, "connect")
	if px.Metrics().Rejected("proxy_auth") != 0 {
		t.Fatal("disabled CONNECT must 403, not 407")
	}
}

func TestHTTPAuthOrigDestNoChallenge(t *testing.T) {
	var hits atomic.Int32
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "od")
	}))
	host, portStr, err := net.SplitHostPort(origin)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	spec := httpAuthSpec(t, true)
	px := startOrigDestProxy(t, net.ParseIP(host), port, Options{Spec: spec, Snapshots: compileSpecSnaps(t, spec)})
	c, err := proxytest.Dial(px.OrigDestAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteRequest("GET /od HTTP/1.1", "Host: "+origin); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "od" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if hits.Load() != 1 {
		t.Fatal("orig-dest must Dial dest-IP without 407")
	}
	if px.Metrics().Rejected("proxy_auth") != 0 {
		t.Fatal("orig-dest must not increment proxy_auth")
	}
}

func compileSpecSnaps(t *testing.T, spec model.Spec) *snapshot.Store {
	t.Helper()
	st := &model.State{
		APIVersion: model.APIVersionV1Alpha1,
		Kind:       model.KindLabMITM,
		Metadata:   model.Metadata{Name: "t"},
		Spec:       spec,
	}
	snap, err := compiler.Compile(t.Context(), st, compiler.CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	snaps := snapshot.NewStore()
	snaps.InstallBootstrap(snap)
	return snaps
}

func TestHTTPAuthInnerInterceptNoChallenge(t *testing.T) {
	var hits atomic.Int32
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("inner origin saw Proxy-Authorization")
		}
		_, _ = io.WriteString(w, "secret")
	}))
	_, port := hostPort(t, origin)
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	spec.Proxy.HTTPAuth = httpAuthSpec(t, true).Proxy.HTTPAuth
	px := startHTTPAuthProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	tr := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{
			Scheme: "http",
			Host:   px.Addr().String(),
			User:   url.UserPassword("labuser", "labpass12"),
		}),
		TLSClientConfig: &tls.Config{
			ServerName: "app.lab",
			RootCAs:    px.Authority().CertPool(),
			NextProtos: []string{"http/1.1"},
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	t.Cleanup(tr.CloseIdleConnections)
	req, err := http.NewRequest(http.MethodGet, "https://app.lab:"+strconv.Itoa(port)+"/hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "secret" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if hits.Load() != 1 {
		t.Fatal("inner GET must reach origin without 407")
	}
}

func TestH2CGETAuthRetry(t *testing.T) {
	var sawAuth string
	hits := atomic.Int32{}
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		sawAuth = r.Header.Get("Proxy-Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	spec := httpAuthSpec(t, true)
	spec.Protocols.HTTP2.ClientCleartext = true
	sink := NewNull()
	px := startHTTPAuthProxy(t, Options{Spec: spec, Sink: sink})
	cc := dialH2C(t, px.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := mustRequest(t, http.MethodGet, originURL+"/hello")
	req = req.WithContext(ctx)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("first status %d", resp.StatusCode)
	}
	if resp.Header.Get("Proxy-Authenticate") == "" {
		t.Fatal("missing Proxy-Authenticate")
	}
	req2 := mustRequest(t, http.MethodGet, originURL+"/hello")
	req2 = req2.WithContext(ctx)
	req2.Header.Set("Proxy-Authorization", "Basic "+httpAuthBasic())
	resp2, err := cc.RoundTrip(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	body, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("retry status %d body %q", resp2.StatusCode, body)
	}
	if sawAuth != "" {
		t.Fatalf("origin saw %q", sawAuth)
	}
	if hits.Load() != 1 {
		t.Fatal("origin GET after retry")
	}
	assertFlowsHideProxyAuth(t, sink)
}

func TestH2CConnectAuthRetry(t *testing.T) {
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
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 16)
		n, _ := c.Read(buf)
		got <- append([]byte(nil), buf[:n]...)
		_, _ = c.Write([]byte("pong"))
	}()

	spec := httpAuthSpec(t, true)
	spec.Protocols.HTTP2.ClientCleartext = true
	px := startHTTPAuthProxy(t, Options{Spec: spec})
	fr, c := h2cRawClient(t, px.Addr().String())
	defer func() { _ = c.Close() }()
	writeH2CHeaders(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":authority", Value: ln.Addr().String()},
	}, false)
	st, hdrs := readH2CStatusHeaders(t, fr, 1)
	if st != http.StatusProxyAuthRequired {
		t.Fatalf("status %d want 407 (empty-header accept hole)", st)
	}
	found := false
	for _, h := range hdrs {
		if strings.EqualFold(h.Name, "proxy-authenticate") && strings.Contains(h.Value, `Basic realm="labmitm-proxy"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("407 headers %+v", hdrs)
	}
	writeH2CHeaders(t, fr, 3, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":authority", Value: ln.Addr().String()},
		{Name: "proxy-authorization", Value: "Basic " + httpAuthBasic()},
	}, false)
	st2 := readH2CStatus(t, fr, 3)
	if st2 != http.StatusOK {
		t.Fatalf("retry status %d want 200 (h2cConnectRequest must copy headers)", st2)
	}
	if err := fr.WriteData(3, false, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-got:
		if string(b) != "ping" {
			t.Fatalf("origin %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("origin did not see spliced DATA")
	}
}

func TestH2CExtendedConnectNot407(t *testing.T) {
	origin := echoWSOrigin(t)
	spec := httpAuthSpec(t, true)
	spec.Protocols.HTTP2.ClientCleartext = true
	spec.Protocols.HTTP2.ExtendedConnect = true
	px := startHTTPAuthProxy(t, Options{Spec: spec})
	fr, c := h2cRawClient(t, px.Addr().String())
	defer func() { _ = c.Close() }()
	writeH2CHeaders(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":protocol", Value: "websocket"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: origin},
		{Name: ":path", Value: "/ws"},
		{Name: "sec-websocket-version", Value: "13"},
	}, false)
	st := readH2CStatus(t, fr, 1)
	if st == http.StatusProxyAuthRequired {
		t.Fatal("Extended CONNECT must not be 407'd by httpAuth")
	}
	if st != http.StatusOK {
		t.Fatalf("status %d want 200", st)
	}
}

func TestHTTPAuthLiveFlipNextRequest(t *testing.T) {
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	off := httpAuthSpec(t, false)
	st := &model.State{APIVersion: model.APIVersionV1Alpha1, Kind: model.KindLabMITM, Metadata: model.Metadata{Name: "t"}, Spec: off}
	first, err := compiler.Compile(t.Context(), st, compiler.CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	snaps := snapshot.NewStore()
	snaps.InstallBootstrap(first)
	px := startProxy(t, Options{Spec: first.Canonical.Spec, Snapshots: snaps, Authority: first.CA})
	if via := throughProxy(t, px.Addr().String(), originURL+"/x"); via != "ok" {
		t.Fatalf("flag-off body %q", via)
	}

	on := httpAuthSpec(t, true)
	nextState := &model.State{APIVersion: model.APIVersionV1Alpha1, Kind: model.KindLabMITM, Metadata: model.Metadata{Name: "t"}, Spec: on}
	next, err := compiler.Compile(t.Context(), nextState, compiler.CompileOpts{Previous: first, ReloadHTTPAuth: true, Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	snaps.Swap(next)

	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteRequest("GET "+originURL+"/y HTTP/1.1", "Host: "+mustURL(t, originURL).Host); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("after live flip status %d", resp.StatusCode)
	}
}

func TestHTTPAuthLiveFlipInFlightCONNECT(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan []byte, 2)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 16)
		n, _ := c.Read(buf)
		got <- append([]byte(nil), buf[:n]...)
		_, _ = c.Write([]byte("pong"))
		n, _ = c.Read(buf)
		got <- append([]byte(nil), buf[:n]...)
	}()

	off := httpAuthSpec(t, false)
	st := &model.State{APIVersion: model.APIVersionV1Alpha1, Kind: model.KindLabMITM, Metadata: model.Metadata{Name: "t"}, Spec: off}
	first, err := compiler.Compile(t.Context(), st, compiler.CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	snaps := snapshot.NewStore()
	snaps.InstallBootstrap(first)
	px := startProxy(t, Options{Spec: first.Canonical.Spec, Snapshots: snaps, Authority: first.CA})

	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	host := ln.Addr().String()
	if err := c.WriteRequest("CONNECT "+host+" HTTP/1.1", "Host: "+host); err != nil {
		t.Fatal(err)
	}
	stLine, err := c.ReadLine()
	if err != nil {
		t.Fatal(err)
	}
	if stLine != "HTTP/1.1 200 Connection Established" {
		t.Fatalf("status %q", stLine)
	}
	if blank, err := c.ReadLine(); err != nil || blank != "" {
		t.Fatalf("blank %q err=%v", blank, err)
	}
	if err := c.WriteRaw([]byte("ping1")); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-got:
		if string(b) != "ping1" {
			t.Fatalf("origin %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("origin did not see first splice")
	}

	on := httpAuthSpec(t, true)
	nextState := &model.State{APIVersion: model.APIVersionV1Alpha1, Kind: model.KindLabMITM, Metadata: model.Metadata{Name: "t"}, Spec: on}
	next, err := compiler.Compile(t.Context(), nextState, compiler.CompileOpts{Previous: first, ReloadHTTPAuth: true, Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	snaps.Swap(next)

	if err := c.WriteRaw([]byte("ping2")); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-got:
		if string(b) != "ping2" {
			t.Fatalf("in-flight CONNECT torn down after live flip: origin %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight CONNECT torn down after live flip")
	}

	c2, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	if err := c2.WriteRequest("GET http://127.0.0.1:9/y HTTP/1.1", "Host: 127.0.0.1:9"); err != nil {
		t.Fatal(err)
	}
	resp, err := c2.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("next absolute-form status %d want 407", resp.StatusCode)
	}
}

func assertFlowsHideProxyAuth(t *testing.T, sink *Null) {
	t.Helper()
	basic := httpAuthBasic()
	for _, f := range sink.Last() {
		for _, h := range f.Request.Headers {
			if strings.EqualFold(h.Name, "Proxy-Authorization") {
				t.Fatalf("flow %s attached Proxy-Authorization", f.ID)
			}
			if strings.Contains(h.Value, "labuser") || strings.Contains(h.Value, "labpass12") || strings.Contains(h.Value, basic) {
				t.Fatalf("flow %s leaked secret in %s", f.ID, h.Name)
			}
		}
		blob := string(f.Request.Body) + f.Error + f.URL
		if strings.Contains(blob, "labpass12") || strings.Contains(blob, basic) {
			t.Fatalf("flow %s leaked secret in body/error/url", f.ID)
		}
	}
}

func TestHTTPAuthSOCKSUnchanged(t *testing.T) {
	spec := userPassSpec(t)
	spec.Proxy.HTTPAuth = httpAuthSpec(t, true).Proxy.HTTPAuth
	px := startUserPassProxy(t, Options{Spec: spec})
	c := socksDial(t, px.Addr().String())
	writeAll(t, c, []byte{0x05, 0x01, 0x02})
	got := readN(t, c, 2)
	if got[0] != 0x05 || got[1] != 0x02 {
		t.Fatalf("greeting %x want 05 02", got)
	}
	rep := socks5UserPassAuth(t, c, "labuser", "labpass12")
	if rep[0] != 0x01 || rep[1] != 0x00 {
		t.Fatalf("auth reply %x want 01 00", rep)
	}
}

func readH2CStatusHeaders(t *testing.T, fr *http2.Framer, id uint32) (int, []hpack.HeaderField) {
	t.Helper()
	dec := hpack.NewDecoder(4096, nil)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch hf := f.(type) {
		case *http2.RSTStreamFrame:
			if hf.StreamID == id {
				t.Fatalf("RST %v", hf.ErrCode)
			}
		case *http2.HeadersFrame:
			if hf.StreamID != id {
				continue
			}
			headers, err := dec.DecodeFull(hf.HeaderBlockFragment())
			if err != nil {
				t.Fatal(err)
			}
			st := 0
			for _, h := range headers {
				if h.Name == ":status" {
					for _, c := range h.Value {
						st = st*10 + int(c-'0')
					}
				}
			}
			return st, headers
		}
	}
	t.Fatal("no response HEADERS")
	return 0, nil
}

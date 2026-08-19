package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/http2x"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
	"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func interceptH2Spec(t *testing.T, originPort int) model.Spec {
	t.Helper()
	spec := interceptSpec(t, originPort, testdataTLS(t, "origin-ca.pem"))
	spec.Protocols.HTTP2.Enabled = true
	return spec
}

func httpsH2ViaProxy(t *testing.T, proxyAddr, originPort, path string, roots *x509.CertPool) (*http.Response, error) {
	t.Helper()
	tr := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
		TLSClientConfig: &tls.Config{
			ServerName: "app.lab",
			RootCAs:    roots,
			NextProtos: []string{http2x.NextProtoH2, tlsmitm.ALPN},
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
	}
	t.Cleanup(tr.CloseIdleConnections)
	req, err := http.NewRequest(http.MethodGet, "https://app.lab:"+originPort+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tr.RoundTrip(req)
}

func h2ClientConnViaProxy(t *testing.T, proxyAddr, originPort string, roots *x509.CertPool) *http2.ClientConn {
	t.Helper()
	c, err := proxytest.Dial(proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	target := net.JoinHostPort("app.lab", originPort)
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
		t.Fatalf("blank %q err=%v", blank, err)
	}
	tlsConn := tls.Client(c.Conn, &tls.Config{
		ServerName: "app.lab",
		RootCAs:    roots,
		NextProtos: []string{http2x.NextProtoH2},
		MinVersion: tls.VersionTLS12,
	})
	t.Cleanup(func() { _ = tlsConn.Close() })
	_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != http2x.NextProtoH2 {
		t.Fatalf("ALPN=%q", tlsConn.ConnectionState().NegotiatedProtocol)
	}
	cc, err := (&http2.Transport{}).NewClientConn(tlsConn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func TestInterceptHTTP2InnerGETStreamID(t *testing.T) {
	var hits atomic.Int32
	var leaked atomic.Bool
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		for name := range r.Header {
			if strings.HasPrefix(name, ":") {
				leaked.Store(true)
				t.Errorf("pseudo leaked to origin %q", name)
			}
		}
		if r.URL.Path != "/hello" {
			t.Errorf("path %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, "h2-body")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2Spec(t, port)
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	resp, err := httpsH2ViaProxy(t, px.Addr().String(), strconv.Itoa(port), "/hello", px.Authority().CertPool())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "h2-body" {
		t.Fatalf("status %d body %q proto %q", resp.StatusCode, body, resp.Proto)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("client proto %q (want HTTP/2)", resp.Proto)
	}
	if hits.Load() != 1 {
		t.Fatalf("origin hits %d", hits.Load())
	}
	if leaked.Load() {
		t.Fatal("origin saw leading-colon headers")
	}
	found := false
	for _, f := range sink.Last() {
		if f.Intercepted && f.Protocol == model.FlowProtocolHTTP2 && strings.Contains(f.URL, "/hello") {
			found = true
			if f.HTTP2 == nil || f.HTTP2.StreamID == 0 {
				t.Fatalf("missing StreamID: %+v", f.HTTP2)
			}
			sawPath := false
			for _, h := range f.Request.Headers {
				if h.Name == ":path" && strings.HasPrefix(h.Value, "/hello") {
					sawPath = true
				}
			}
			if !sawPath {
				t.Fatalf("captured headers missing :path: %+v", f.Request.Headers)
			}
		}
	}
	if !found {
		t.Fatalf("no h2 flow: %+v", sink.Last())
	}
}

func TestInterceptHTTP2RulesMatchPath(t *testing.T) {
	var originHits atomic.Int32
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		_, _ = io.WriteString(w, "origin")
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2Spec(t, port)
	spec.Rules = model.RulesSpec{
		Enabled: true,
		Items: []model.RuleSpec{{
			ID:      "drop-login",
			Enabled: true,
			Phase:   model.RulePhaseRequest,
			Match:   model.RuleMatchSpec{PathPrefix: "/login", HeaderName: ":path"},
			Action:  model.RuleActionSpec{Type: model.ActionDrop, Status: 403},
		}},
	}
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/login?x=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if originHits.Load() != 0 {
		t.Fatal("drop must not reach origin")
	}
	if px.Metrics().RuleHits(model.ActionDrop) < 1 {
		t.Fatal("expected drop hit on :path")
	}
}

func TestInterceptHTTP2InnerCONNECTRejected(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin must not see inner CONNECT")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2Spec(t, port)
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://app.lab/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "app.lab:" + strconv.Itoa(port)
	_, err = cc.RoundTrip(req)
	if err == nil {
		t.Fatal("expected RST on inner CONNECT")
	}
	if ctx.Err() != nil {
		t.Fatalf("timed out: %v", err)
	}
	if px.Metrics().Rejected("http2") < 1 {
		t.Fatal("expected reject reason=http2")
	}
	for _, f := range sink.Last() {
		if f.Intercepted && f.Method == http.MethodConnect && f.Protocol == model.FlowProtocolHTTP2 {
			t.Fatalf("inner CONNECT must not capture a flow: %+v", f)
		}
	}
}

func TestInterceptHTTP2WebsocketRejected(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin must not see websocket upgrade")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2Spec(t, port)
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	// net/http's h2 client refuses Upgrade; send raw HEADERS so the proxy sees them.
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	writeH2Headers(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "app.lab"},
		{Name: ":path", Value: "/ws"},
		{Name: "upgrade", Value: "websocket"},
		{Name: "connection", Value: "Upgrade"},
	}, true)
	expectRSTStream(t, fr, 1, http2.ErrCodeProtocol)
	_ = tlsConn
	if px.Metrics().Rejected("http2") < 1 {
		t.Fatal("expected reject reason=http2")
	}
	for _, f := range sink.Last() {
		if f.Intercepted && f.Protocol == model.FlowProtocolHTTP2 {
			t.Fatalf("websocket upgrade must not capture a flow: %+v", f)
		}
	}
}

func h2RawClientViaProxy(t *testing.T, proxyAddr, originPort string, roots *x509.CertPool) (*http2.Framer, *tls.Conn) {
	t.Helper()
	c, err := proxytest.Dial(proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	target := net.JoinHostPort("app.lab", originPort)
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
		t.Fatalf("blank %q err=%v", blank, err)
	}
	tlsConn := tls.Client(c.Conn, &tls.Config{
		ServerName: "app.lab",
		RootCAs:    roots,
		NextProtos: []string{http2x.NextProtoH2},
		MinVersion: tls.VersionTLS12,
	})
	t.Cleanup(func() { _ = tlsConn.Close() })
	_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsConn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(tlsConn, tlsConn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("settings: %v", err)
		}
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			if err := fr.WriteSettingsAck(); err != nil {
				t.Fatal(err)
			}
			return fr, tlsConn
		}
	}
	t.Fatal("no server SETTINGS")
	return fr, tlsConn
}

func writeH2Headers(t *testing.T, fr *http2.Framer, id uint32, fields []hpack.HeaderField, endStream bool) {
	t.Helper()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, hf := range fields {
		if err := enc.WriteField(hf); err != nil {
			t.Fatal(err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      id,
		BlockFragment: buf.Bytes(),
		EndHeaders:    true,
		EndStream:     endStream,
	}); err != nil {
		t.Fatal(err)
	}
}

func expectRSTStream(t *testing.T, fr *http2.Framer, id uint32, code http2.ErrCode) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		rst, ok := f.(*http2.RSTStreamFrame)
		if !ok {
			continue
		}
		if rst.StreamID != id {
			continue
		}
		if rst.ErrCode != code {
			t.Fatalf("RST code %v want %v", rst.ErrCode, code)
		}
		return
	}
	t.Fatal("no RST_STREAM")
}

func TestInterceptHTTP2Stream502KeepsCONNECT(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			http.Error(w, "nope", http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2Spec(t, port)
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	failReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/fail", nil)
	if err != nil {
		t.Fatal(err)
	}
	failResp, err := cc.RoundTrip(failReq)
	if err != nil {
		var ge http2.GoAwayError
		if errors.As(err, &ge) {
			t.Fatalf("stream 502 GOAWAY: %+v", ge)
		}
		t.Fatalf("fail stream: %v", err)
	}
	defer func() { _ = failResp.Body.Close() }()
	if failResp.StatusCode != http.StatusBadGateway {
		t.Fatalf("fail status %d", failResp.StatusCode)
	}

	okReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/ok", nil)
	if err != nil {
		t.Fatal(err)
	}
	okResp, err := cc.RoundTrip(okReq)
	if err != nil {
		var ge http2.GoAwayError
		if errors.As(err, &ge) {
			t.Fatalf("second stream GOAWAY: %+v", ge)
		}
		t.Fatalf("second stream: %v", err)
	}
	defer func() { _ = okResp.Body.Close() }()
	body, _ := io.ReadAll(okResp.Body)
	if okResp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("ok status %d body %q", okResp.StatusCode, body)
	}
}

func TestInterceptHTTP2PausedRequestDoesNotBlockSecondStream(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pause" {
			t.Errorf("origin should not be reached for %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, "resumed")
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2Spec(t, port)
	spec.Rules = model.RulesSpec{
		Enabled: true,
		Items: []model.RuleSpec{
			{
				ID:      "pause",
				Enabled: true,
				Phase:   model.RulePhaseRequest,
				Match:   model.RuleMatchSpec{PathPrefix: "/pause"},
				Action:  model.RuleActionSpec{Type: model.ActionBreakpoint, Breakpoint: model.RuleBreakpointSpec{Timeout: 5 * time.Second}},
			},
			{
				ID:      "other",
				Enabled: true,
				Phase:   model.RulePhaseRequest,
				Match:   model.RuleMatchSpec{PathPrefix: "/other"},
				Action:  model.RuleActionSpec{Type: model.ActionStatus, Status: 418},
			},
		},
	}
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: time.Minute})
	px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Store: inbox, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())

	pausedDone := make(chan *http.Response, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/pause", nil)
		if err != nil {
			t.Error(err)
			pausedDone <- nil
			return
		}
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Error(err)
			pausedDone <- nil
			return
		}
		pausedDone <- resp
	}()

	paused := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/pause"})
	if paused.State != model.FlowStatePaused {
		t.Fatalf("state %q", paused.State)
	}

	otherDone := make(chan int, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/other", nil)
		if err != nil {
			t.Error(err)
			otherDone <- -1
			return
		}
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Error(err)
			otherDone <- -1
			return
		}
		defer func() { _ = resp.Body.Close() }()
		otherDone <- resp.StatusCode
	}()

	select {
	case code := <-otherDone:
		if code != 418 {
			t.Fatalf("second stream status %d (paused request must not block request-phase rules)", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("paused request-phase stream blocked a second stream")
	}

	if err := inbox.Resume(paused.ID, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-pausedDone:
		if resp != nil {
			_ = resp.Body.Close()
		}
	case <-time.After(3 * time.Second):
		t.Fatal("paused stream hung after resume")
	}
}

func TestH2InnerForbidden(t *testing.T) {
	if !h2InnerForbidden(http2x.Stream{Method: http.MethodConnect}) {
		t.Fatal("CONNECT")
	}
	if !h2InnerForbidden(http2x.Stream{
		Method:  http.MethodGet,
		Pseudos: []model.Header{{Name: ":protocol", Value: "websocket"}},
	}) {
		t.Fatal(":protocol")
	}
	if !h2InnerForbidden(http2x.Stream{
		Method: http.MethodGet,
		Headers: []model.Header{
			{Name: "Upgrade", Value: "websocket"},
			{Name: "Connection", Value: "Upgrade"},
		},
	}) {
		t.Fatal("websocket upgrade")
	}
	if h2InnerForbidden(http2x.Stream{Method: http.MethodGet, Path: "/ok"}) {
		t.Fatal("ordinary GET")
	}
}

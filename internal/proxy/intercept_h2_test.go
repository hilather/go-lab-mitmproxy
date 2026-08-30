package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/http2x"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
	"github.com/hilather/go-lab-mitmproxy/internal/rules"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
	"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm"
	"github.com/hilather/go-lab-mitmproxy/internal/wsx"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func interceptH2Spec(t *testing.T, originPort int) model.Spec {
	t.Helper()
	spec := interceptSpec(t, originPort, testdataTLS(t, "origin-ca.pem"))
	spec.Protocols.HTTP2.Enabled = true
	return spec
}

func interceptH2OriginSpec(t *testing.T, originPort int) model.Spec {
	t.Helper()
	spec := interceptH2Spec(t, originPort)
	spec.Protocols.HTTP2.Origin = true
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

func expectH2Response(t *testing.T, fr *http2.Framer, id uint32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch hf := f.(type) {
		case *http2.HeadersFrame:
			if hf.StreamID == id {
				return
			}
		case *http2.MetaHeadersFrame:
			if hf.StreamID == id {
				return
			}
		case *http2.RSTStreamFrame:
			if hf.StreamID == id {
				t.Fatalf("RST %v", hf.ErrCode)
			}
		}
	}
	t.Fatal("no response HEADERS")
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

func TestInterceptHTTP2ResponseThrottleDoesNotHoldOriginMu(t *testing.T) {
	payload := bytes.Repeat([]byte("h"), 32<<10)
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			_, _ = w.Write(payload)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2Spec(t, port)
	spec.Rules = model.RulesSpec{
		Enabled: true,
		Items: []model.RuleSpec{{
			ID:      "slow-h2",
			Enabled: true,
			Phase:   model.RulePhaseResponse,
			Match:   model.RuleMatchSpec{PathPrefix: "/big"},
			Action:  model.RuleActionSpec{Type: model.ActionThrottle, BytesPerSecond: 8 << 10},
		}},
	}
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())

	headersSeen := make(chan *http.Response, 1)
	bodyDone := make(chan struct {
		d   time.Duration
		n   int
		err error
	}, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/big", nil)
		if err != nil {
			t.Error(err)
			headersSeen <- nil
			return
		}
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Error(err)
			headersSeen <- nil
			return
		}
		headersSeen <- resp
		start := time.Now()
		got, rerr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		bodyDone <- struct {
			d   time.Duration
			n   int
			err error
		}{time.Since(start), len(got), rerr}
	}()

	var first *http.Response
	select {
	case first = <-headersSeen:
		if first == nil {
			t.Fatal("throttled stream failed")
		}
		if first.StatusCode != http.StatusOK {
			t.Fatalf("throttled status %d", first.StatusCode)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("throttled stream headers never arrived")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/other", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("second stream blocked by response throttle: %v", err)
	}
	defer func() { _ = second.Body.Close() }()
	b, _ := io.ReadAll(second.Body)
	if second.StatusCode != http.StatusOK || string(b) != "ok" {
		t.Fatalf("second stream %d %q", second.StatusCode, b)
	}

	select {
	case body := <-bodyDone:
		if body.err != nil {
			t.Fatalf("throttled body: %v", body.err)
		}
		if body.n != len(payload) {
			t.Fatalf("throttled body len %d", body.n)
		}
		if body.d < 3*time.Second {
			t.Fatalf("client body elapsed %s want >= 3s (~4s at 8KiB/s)", body.d)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("throttled body never finished")
	}
	if px.Metrics().RuleHits(model.ActionThrottle) < 1 {
		t.Fatal("expected throttle hit")
	}
}

func TestInterceptHTTP2ConcurrentStreamsSerializeOnH1Origin(t *testing.T) {
	var inflight atomic.Int32
	var maxInflight atomic.Int32
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inflight.Add(1)
		defer inflight.Add(-1)
		for {
			old := maxInflight.Load()
			if n <= old || maxInflight.CompareAndSwap(old, n) {
				break
			}
		}
		if fl, ok := w.(http.Flusher); ok {
			_, _ = io.WriteString(w, "part-")
			fl.Flush()
			time.Sleep(80 * time.Millisecond)
			_, _ = io.WriteString(w, r.URL.Path)
			return
		}
		_, _ = io.WriteString(w, "part-"+r.URL.Path)
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2Spec(t, port)
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())

	var wg sync.WaitGroup
	type result struct {
		path string
		body string
		err  error
	}
	out := make(chan result, 2)
	for _, path := range []string{"/a", "/b"} {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab"+path, nil)
			if err != nil {
				out <- result{path: path, err: err}
				return
			}
			resp, err := cc.RoundTrip(req)
			if err != nil {
				out <- result{path: path, err: err}
				return
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				out <- result{path: path, err: fmt.Errorf("status %d", resp.StatusCode)}
				return
			}
			out <- result{path: path, body: string(body)}
		}(path)
	}
	wg.Wait()
	close(out)
	got := map[string]string{}
	for r := range out {
		if r.err != nil {
			if strings.Contains(r.err.Error(), "refuses redial") {
				t.Fatalf("concurrent streams redialed: %v", r.err)
			}
			var ge http2.GoAwayError
			if errors.As(r.err, &ge) {
				t.Fatalf("GOAWAY: %+v", ge)
			}
			t.Fatalf("%s: %v", r.path, r.err)
		}
		got[r.path] = r.body
	}
	if got["/a"] != "part-/a" || got["/b"] != "part-/b" {
		t.Fatalf("bodies %#v", got)
	}
	if maxInflight.Load() != 1 {
		t.Fatalf("h1 origin saw concurrent requests: max=%d", maxInflight.Load())
	}
}

func TestInterceptHTTP2OriginH2MultiplexTwoStreams(t *testing.T) {
	var inflight atomic.Int32
	var maxInflight atomic.Int32
	var sawH2 atomic.Bool
	var conns atomic.Int32
	origin := startTLSOriginH2State(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			sawH2.Store(true)
		}
		n := inflight.Add(1)
		defer inflight.Add(-1)
		for {
			old := maxInflight.Load()
			if n <= old || maxInflight.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(80 * time.Millisecond)
		_, _ = io.WriteString(w, r.URL.Path)
	}), func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			conns.Add(1)
		}
	})
	_, port := hostPort(t, origin)
	spec := interceptH2OriginSpec(t, port)
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())

	var wg sync.WaitGroup
	type result struct {
		path string
		body string
		err  error
	}
	out := make(chan result, 2)
	for _, path := range []string{"/a", "/b"} {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab"+path, nil)
			if err != nil {
				out <- result{path: path, err: err}
				return
			}
			resp, err := cc.RoundTrip(req)
			if err != nil {
				out <- result{path: path, err: err}
				return
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				out <- result{path: path, err: fmt.Errorf("status %d", resp.StatusCode)}
				return
			}
			out <- result{path: path, body: string(body)}
		}(path)
	}
	wg.Wait()
	close(out)
	got := map[string]string{}
	for r := range out {
		if r.err != nil {
			if strings.Contains(r.err.Error(), "refuses redial") {
				t.Fatalf("concurrent streams redialed: %v", r.err)
			}
			t.Fatalf("%s: %v", r.path, r.err)
		}
		got[r.path] = r.body
	}
	if got["/a"] != "/a" || got["/b"] != "/b" {
		t.Fatalf("bodies %#v", got)
	}
	if !sawH2.Load() {
		t.Fatal("origin did not negotiate h2")
	}
	if maxInflight.Load() < 2 {
		t.Fatalf("origin h2 must multiplex without D44 mutex: max=%d", maxInflight.Load())
	}
	if conns.Load() != 1 {
		t.Fatalf("second origin TCP forbidden: conns=%d", conns.Load())
	}
}

func TestInterceptHTTP2OriginH2POSTBody(t *testing.T) {
	var sawH2 atomic.Bool
	var got atomic.Value
	origin := startTLSOriginH2(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			sawH2.Store(true)
		}
		b, _ := io.ReadAll(r.Body)
		got.Store(string(b))
		_, _ = io.WriteString(w, "echo:"+string(b))
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2OriginSpec(t, port)
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())

	pr, pw := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.lab/echo", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = -1 // no content-length; typical gRPC / h2 POST
	go func() {
		_, _ = io.WriteString(pw, "hello")
		_ = pw.Close()
	}()
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "echo:hello" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if !sawH2.Load() {
		t.Fatal("origin did not negotiate h2")
	}
	if s, _ := got.Load().(string); s != "hello" {
		t.Fatalf("origin body %q (OriginConn dropped POST DATA)", s)
	}
}

func TestReconstructH2RequestUnknownBodyLength(t *testing.T) {
	req := reconstructH2Request(http2x.Stream{
		Method:    http.MethodPost,
		Path:      "/echo",
		Authority: "app.lab",
		Body:      io.NopCloser(strings.NewReader("hello")),
	})
	if req.ContentLength != -1 {
		t.Fatalf("ContentLength=%d want -1 (omitted content-length)", req.ContentLength)
	}
	reqCL := reconstructH2Request(http2x.Stream{
		Method:    http.MethodPost,
		Path:      "/echo",
		Authority: "app.lab",
		Headers:   []model.Header{{Name: "content-length", Value: "5"}},
		Body:      io.NopCloser(strings.NewReader("hello")),
	})
	if reqCL.ContentLength != 5 {
		t.Fatalf("ContentLength=%d want 5", reqCL.ContentLength)
	}
}

func TestInterceptHTTP2OriginH2StreamErrorKeepsSibling(t *testing.T) {
	slowEntered := make(chan struct{})
	var conns atomic.Int32
	origin := startTLSOriginH2State(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			panic(http.ErrAbortHandler)
		}
		close(slowEntered)
		time.Sleep(150 * time.Millisecond)
		_, _ = io.WriteString(w, "slow-ok")
	}), func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			conns.Add(1)
		}
	})
	_, port := hostPort(t, origin)
	spec := interceptH2OriginSpec(t, port)
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())

	slowDone := make(chan resultH2, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/slow", nil)
		if err != nil {
			slowDone <- resultH2{err: err}
			return
		}
		resp, err := cc.RoundTrip(req)
		if err != nil {
			slowDone <- resultH2{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		slowDone <- resultH2{status: resp.StatusCode, body: string(body)}
	}()
	select {
	case <-slowEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("slow origin handler did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	failReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/fail", nil)
	if err != nil {
		t.Fatal(err)
	}
	failResp, failErr := cc.RoundTrip(failReq)
	if failResp != nil {
		_, _ = io.Copy(io.Discard, failResp.Body)
		_ = failResp.Body.Close()
	}
	if failErr == nil && failResp != nil && failResp.StatusCode != http.StatusBadGateway {
		t.Fatalf("fail want 502 or stream error, status=%d", failResp.StatusCode)
	}
	slow := <-slowDone
	if slow.err != nil {
		if strings.Contains(slow.err.Error(), "refuses redial") {
			t.Fatalf("sibling killed shared origin TCP: %v", slow.err)
		}
		t.Fatalf("slow sibling: %v", slow.err)
	}
	if slow.status != http.StatusOK || slow.body != "slow-ok" {
		t.Fatalf("slow sibling status=%d body=%q", slow.status, slow.body)
	}
	if conns.Load() != 1 {
		t.Fatalf("second origin TCP forbidden: conns=%d", conns.Load())
	}
}

type resultH2 struct {
	status int
	body   string
	err    error
}

func TestInterceptHTTP2InnerHTTP11OriginFlagDoesNotOfferH2(t *testing.T) {
	var proto string
	origin := startTLSOriginH2(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto = r.Proto
		_, _ = io.WriteString(w, "h1-inner")
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2OriginSpec(t, port)
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	resp, err := httpsViaProxy(t, px.Addr().String(), strconv.Itoa(port), "/hello", px.Authority().CertPool())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "h1-inner" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if resp.ProtoMajor != 1 {
		t.Fatalf("client proto %q", resp.Proto)
	}
	if proto != "HTTP/1.1" {
		t.Fatalf("inner http/1.1 offered origin h2: proto %q", proto)
	}
}

func TestInterceptHTTP2OriginFlagOriginH1StillSerializes(t *testing.T) {
	var inflight atomic.Int32
	var maxInflight atomic.Int32
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			t.Error("origin flag on with h1-only origin must not speak h2")
		}
		n := inflight.Add(1)
		defer inflight.Add(-1)
		for {
			old := maxInflight.Load()
			if n <= old || maxInflight.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(80 * time.Millisecond)
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2OriginSpec(t, port)
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	var wg sync.WaitGroup
	out := make(chan error, 2)
	for _, path := range []string{"/a", "/b"} {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab"+path, nil)
			if err != nil {
				out <- err
				return
			}
			resp, err := cc.RoundTrip(req)
			if err != nil {
				out <- err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			out <- nil
		}(path)
	}
	wg.Wait()
	close(out)
	for err := range out {
		if err != nil {
			t.Fatal(err)
		}
	}
	if maxInflight.Load() != 1 {
		t.Fatalf("origin h1 still serializes (D44): max=%d", maxInflight.Load())
	}
}

func TestInterceptHTTP2PausedResponseDoesNotBlockSecondStream(t *testing.T) {
	const pausedBody = "non-empty-origin-body"
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pause" {
			_, _ = io.WriteString(w, pausedBody)
			return
		}
		_, _ = io.WriteString(w, "fast")
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2Spec(t, port)
	spec.Rules = model.RulesSpec{
		Enabled: true,
		Items: []model.RuleSpec{{
			ID:      "pause-resp",
			Enabled: true,
			Phase:   model.RulePhaseResponse,
			Match:   model.RuleMatchSpec{PathPrefix: "/pause"},
			Action:  model.RuleActionSpec{Type: model.ActionBreakpoint, Breakpoint: model.RuleBreakpointSpec{Timeout: 8 * time.Second}},
		}},
	}
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: time.Minute})
	px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Store: inbox, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())

	pausedDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/pause", nil)
		if err != nil {
			pausedDone <- err
			return
		}
		resp, err := cc.RoundTrip(req)
		if err != nil {
			pausedDone <- err
			return
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.ReadAll(resp.Body)
		pausedDone <- nil
	}()

	paused := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/pause"})
	if paused.State != model.FlowStatePaused {
		t.Fatalf("state %q", paused.State)
	}
	if string(paused.Response.Body) != pausedBody {
		t.Fatalf("paused body %q (want non-empty origin body)", paused.Response.Body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/fast", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		if strings.Contains(err.Error(), "refuses redial") {
			t.Fatalf("paused response held origin mutex: %v", err)
		}
		var ge http2.GoAwayError
		if errors.As(err, &ge) {
			t.Fatalf("GOAWAY: %+v", ge)
		}
		t.Fatalf("second stream: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "fast" {
		t.Fatalf("fast status %d body %q", resp.StatusCode, body)
	}

	if err := inbox.Resume(paused.ID, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-pausedDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("paused stream hung after resume")
	}
}

func TestInterceptHTTP2TrailersDroppedTowardH1Origin(t *testing.T) {
	var leaked atomic.Bool
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Trailer") != "" || r.Header.Get("X-Checksum") != "" {
			leaked.Store(true)
		}
		for name := range r.Header {
			if strings.EqualFold(name, "Trailer") || strings.HasPrefix(name, ":") {
				leaked.Store(true)
			}
		}
		_, _ = io.WriteString(w, "ok")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2Spec(t, port)
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	writeH2Headers(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "app.lab"},
		{Name: ":path", Value: "/t"},
		{Name: "trailer", Value: "x-checksum"},
		{Name: "content-length", Value: "2"},
	}, false)
	if err := fr.WriteData(1, false, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	writeH2Headers(t, fr, 1, []hpack.HeaderField{
		{Name: "x-checksum", Value: "abc"},
	}, true)
	expectH2Response(t, fr, 1)
	_ = tlsConn
	if leaked.Load() {
		t.Fatal("request trailer leaked to HTTP/1.1 origin")
	}
	if px.Metrics().H2TrailerDropped() < 1 {
		t.Fatal("expected h2_trailer_dropped")
	}
}

func TestInterceptHTTP2OriginH2ForwardsResponseTrailers(t *testing.T) {
	origin := startTLSOriginH2(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("origin proto %d", r.ProtoMajor)
		}
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "proto")
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "ok")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2OriginSpec(t, port)
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.lab/svc/Echo", strings.NewReader("in"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "proto" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("inner client missing grpc-status trailer: %v", resp.Trailer)
	}
	if got := resp.Trailer.Get("Grpc-Message"); got != "ok" {
		t.Fatalf("inner client missing grpc-message trailer: %v", resp.Trailer)
	}
	deadline := time.Now().Add(3 * time.Second)
	var flow *model.Flow
	for time.Now().Before(deadline) {
		for _, f := range sink.Last() {
			if f.Intercepted && f.Protocol == model.FlowProtocolHTTP2 && strings.Contains(f.URL, "/svc/Echo") {
				flow = f
			}
		}
		if flow != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if flow == nil {
		t.Fatalf("no h2 flow: %+v", sink.Last())
	}
	sawStatus, sawMsg := false, false
	for _, h := range flow.Response.Trailers {
		if strings.EqualFold(h.Name, "Grpc-Status") && h.Value == "0" {
			sawStatus = true
		}
		if strings.EqualFold(h.Name, "Grpc-Message") && h.Value == "ok" {
			sawMsg = true
		}
	}
	if !sawStatus || !sawMsg {
		t.Fatalf("captured trailers %+v", flow.Response.Trailers)
	}
}

func TestStripLeadingColonHeaders(t *testing.T) {
	h := make(http.Header)
	h.Add(":method", "GET")
	h.Add(":authority", "app.lab")
	h.Add("User-Agent", "lab")
	stripLeadingColonHeaders(h)
	if h.Get(":method") != "" || h.Get(":authority") != "" {
		t.Fatalf("pseudos remain: %v", h)
	}
	if h.Get("User-Agent") != "lab" {
		t.Fatalf("regular header %v", h)
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

func interceptH2ExtendedSpec(t *testing.T, originPort int) model.Spec {
	t.Helper()
	spec := interceptH2Spec(t, originPort)
	spec.Protocols.HTTP2.ExtendedConnect = true
	return spec
}

type wsOriginSaw struct {
	upgrades atomic.Int32
	origin   atomic.Value
	cookie   atomic.Value
}

func (s *wsOriginSaw) Origin() string {
	v, _ := s.origin.Load().(string)
	return v
}

func (s *wsOriginSaw) Cookie() string {
	v, _ := s.cookie.Load().(string)
	return v
}

func echoTLSWebSocketOrigin(t *testing.T) (port int, saw *wsOriginSaw) {
	t.Helper()
	saw = &wsOriginSaw{}
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			t.Errorf("origin method=%s upgrade=%q", r.Method, r.Header.Get("Upgrade"))
			http.Error(w, "no upgrade", 400)
			return
		}
		if strings.EqualFold(r.Method, http.MethodConnect) {
			t.Error("origin must see GET Upgrade, not CONNECT")
		}
		saw.origin.Store(r.Header.Get("Origin"))
		saw.cookie.Store(r.Header.Get("Cookie"))
		saw.upgrades.Add(1)
		proto := firstCSV(r.Header.Get("Sec-WebSocket-Protocol"))
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		c, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
		if proto != "" {
			_, _ = fmt.Fprintf(bufrw, "Sec-WebSocket-Protocol: %s\r\n", proto)
		}
		_, _ = io.WriteString(bufrw, "\r\n")
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
	_, port = hostPort(t, origin)
	return port, saw
}

func echoH2WebSocketOrigin(t *testing.T) (port int, saw *wsOriginSaw, accepts *atomic.Int32) {
	t.Helper()
	saw = &wsOriginSaw{}
	accepts = new(atomic.Int32)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{originCert(t)},
		NextProtos:   []string{http2x.NextProtoH2},
		MinVersion:   tls.VersionTLS12,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				tc := tls.Server(c, cfg)
				if err := tc.Handshake(); err != nil {
					return
				}
				h := func(context.Context, http2x.Stream) (*http.Response, []model.Header, error) {
					return nil, nil, errors.New("origin h2 echo: unexpected request")
				}
				tun := func(_ context.Context, in http2x.Stream) (http2x.Tunnel, error) {
					if !strings.EqualFold(in.Method, http.MethodConnect) || !strings.EqualFold(in.Protocol, "websocket") {
						t.Errorf("origin method=%s protocol=%q", in.Method, in.Protocol)
						return http2x.Tunnel{}, http2x.ErrInnerCONNECT
					}
					saw.origin.Store(headerValue(in.Headers, "origin"))
					saw.cookie.Store(headerValue(in.Headers, "cookie"))
					saw.upgrades.Add(1)
					return http2x.Tunnel{
						Kind: http2x.TunnelWebSocket,
						AfterAck: func(client net.Conn) {
							if client == nil {
								return
							}
							for {
								fr, err := wsx.ReadFrame(client, 0)
								if err != nil {
									return
								}
								fr.Masked = false
								fr.MaskKey = [4]byte{}
								if err := wsx.WriteFrame(client, fr); err != nil {
									return
								}
								if fr.Opcode == wsx.OpcodeClose {
									return
								}
							}
						},
					}, nil
				}
				_ = http2x.ServeConn(ctx, tc, nil, http2x.ServeOpts{
					Preface:               http2x.PrefaceFull,
					EnableConnectProtocol: true,
				}, h, tun)
			}(c)
		}
	}()
	_, port = hostPort(t, ln.Addr().String())
	return port, saw, accepts
}

func firstCSV(v string) string {
	for tok := range strings.SplitSeq(v, ",") {
		s := strings.TrimSpace(tok)
		if s != "" {
			return s
		}
	}
	return ""
}

func writeExtendedCONNECT(t *testing.T, fr *http2.Framer, extra ...hpack.HeaderField) {
	t.Helper()
	fields := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":protocol", Value: "websocket"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "app.lab"},
		{Name: ":path", Value: "/ws"},
		{Name: "sec-websocket-version", Value: "13"},
	}
	writeH2Headers(t, fr, 1, append(fields, extra...), false)
}

func echoWSClient(t *testing.T, fr *http2.Framer, tlsConn *tls.Conn) {
	t.Helper()
	_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
	var payload bytes.Buffer
	if err := wsx.WriteFrame(&payload, wsx.Frame{
		Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("h2ws"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteData(1, false, payload.Bytes()); err != nil {
		t.Fatal(err)
	}
	echo := readH2WebSocketFrame(t, fr, 1)
	if echo.Opcode != wsx.OpcodeText || string(echo.Payload) != "h2ws" {
		t.Fatalf("echo %+v", echo)
	}
	payload.Reset()
	if err := wsx.WriteFrame(&payload, wsx.Frame{
		Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteData(1, false, payload.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func TestInterceptHTTP2ExtendedCONNECTRejectedFlagOff(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin must not see Extended CONNECT when flag off")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2Spec(t, port)
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	writeH2Headers(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":protocol", Value: "websocket"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "app.lab"},
		{Name: ":path", Value: "/ws"},
	}, false)
	expectRSTStream(t, fr, 1, http2.ErrCodeProtocol)
	_ = tlsConn
	if px.Metrics().Rejected("http2") < 1 {
		t.Fatal("expected reject reason=http2")
	}
	assertNoH2ConnectFlow(t, sink)
}

func TestInterceptHTTP2InnerCONNECTRejectedExtendedConnectOn(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin must not see nested inner CONNECT")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2ExtendedSpec(t, port)
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	writeH2Headers(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":authority", Value: "app.lab:" + strconv.Itoa(port)},
	}, false)
	expectRSTStream(t, fr, 1, http2.ErrCodeProtocol)
	_ = tlsConn
	if px.Metrics().Rejected("http2") < 1 {
		t.Fatal("expected reject reason=http2")
	}
	assertNoH2ConnectFlow(t, sink)
}

func TestInterceptHTTP2OtherProtocolRST(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin must not see :protocol=foo")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2ExtendedSpec(t, port)
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	writeH2Headers(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":protocol", Value: "foo"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "app.lab"},
		{Name: ":path", Value: "/x"},
	}, false)
	expectRSTStream(t, fr, 1, http2.ErrCodeProtocol)
	_ = tlsConn
	if px.Metrics().Rejected("http2") < 1 {
		t.Fatal("expected reject reason=http2")
	}
	assertNoH2ConnectFlow(t, sink)
}

func TestInterceptHTTP2WebsocketUpgradeRejectedExtendedConnectOn(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin must not see h2 Upgrade: websocket")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2ExtendedSpec(t, port)
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
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

func TestInterceptHTTP2ExtendedCONNECTWebsocket(t *testing.T) {
	port, saw := echoTLSWebSocketOrigin(t)
	sink := NewNull()
	spec := interceptH2ExtendedSpec(t, port)
	spec.Protocols.WebSocket.InspectFrames = true
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
	writeExtendedCONNECT(t, fr,
		hpack.HeaderField{Name: "origin", Value: "https://app.lab"},
		hpack.HeaderField{Name: "cookie", Value: "sid=1"},
		hpack.HeaderField{Name: "sec-websocket-protocol", Value: "chat, superchat"},
	)
	fields := readH2HeaderFields(t, fr, 1)
	if h2Field(fields, ":status") != "200" {
		t.Fatalf("status fields %+v", fields)
	}
	if h2Field(fields, "sec-websocket-protocol") != "chat" {
		t.Fatalf("selected protocol %+v", fields)
	}
	if h2Field(fields, "upgrade") != "" || h2Field(fields, "connection") != "" {
		t.Fatalf("hop headers on 200: %+v", fields)
	}
	echoWSClient(t, fr, tlsConn)
	if saw.upgrades.Load() != 1 {
		t.Fatalf("origin upgrades %d", saw.upgrades.Load())
	}
	if saw.Origin() != "https://app.lab" || saw.Cookie() != "sid=1" {
		t.Fatalf("origin=%q cookie=%q", saw.Origin(), saw.Cookie())
	}
	f := waitWSFlow(t, sink)
	if !f.Intercepted || f.Status != http.StatusOK {
		t.Fatalf("flow %+v", f)
	}
	if f.Method != http.MethodConnect {
		t.Fatalf("method %q want CONNECT", f.Method)
	}
	if f.HTTP2 == nil || f.HTTP2.StreamID == 0 {
		t.Fatalf("missing StreamID: %+v", f.HTTP2)
	}
	if f.WebSocket == nil || f.WebSocket.FrameCount < 1 {
		t.Fatalf("want frames, got %+v", f.WebSocket)
	}
}

func TestInterceptHTTP2ExtendedCONNECTWebsocketFrameDrop(t *testing.T) {
	port, saw := echoTLSWebSocketOrigin(t)
	spec := interceptH2ExtendedSpec(t, port)
	spec.Protocols.WebSocket.InspectFrames = true
	spec.Rules = model.RulesSpec{
		Enabled: true,
		Items: []model.RuleSpec{{
			ID:      "drop-text",
			Enabled: true,
			Phase:   model.RulePhaseWebSocket,
			Match:   model.RuleMatchSpec{Opcode: model.RuleOpcodeText},
			Action:  model.RuleActionSpec{Type: model.ActionDrop},
		}},
	}
	sink := NewNull()
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	writeExtendedCONNECT(t, fr)
	fields := readH2HeaderFields(t, fr, 1)
	if h2Field(fields, ":status") != "200" {
		t.Fatalf("status fields %+v", fields)
	}
	var payload bytes.Buffer
	if err := wsx.WriteFrame(&payload, wsx.Frame{
		Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("h2ws"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteData(1, false, payload.Bytes()); err != nil {
		t.Fatal(err)
	}
	payload.Reset()
	if err := wsx.WriteFrame(&payload, wsx.Frame{
		Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteData(1, false, payload.Bytes()); err != nil {
		t.Fatal(err)
	}
	_ = tlsConn
	f := waitWSFlow(t, sink)
	if f.Method != http.MethodConnect {
		t.Fatalf("method %q want CONNECT", f.Method)
	}
	if saw.upgrades.Load() != 1 {
		t.Fatalf("origin upgrades %d", saw.upgrades.Load())
	}
	if px.Metrics().RuleHits(model.ActionDrop) < 1 {
		t.Fatal("D63 inspect must inherit websocket-phase drop")
	}
	if px.Metrics().WSFrames("text") != 0 {
		t.Fatal("dropped D63 text must not increment ws_frames_total")
	}
}

func TestInterceptHTTP2ExtendedCONNECTResponseLateSkip(t *testing.T) {
	port, _ := echoTLSWebSocketOrigin(t)
	spec := interceptH2ExtendedSpec(t, port)
	spec.Protocols.WebSocket.InspectFrames = true
	spec.Rules = model.RulesSpec{
		Enabled: true,
		Items: []model.RuleSpec{
			{ID: "resp-drop", Enabled: true, Phase: model.RulePhaseResponse, Action: model.RuleActionSpec{Type: model.ActionDrop}},
			{ID: "resp-delay", Enabled: true, Phase: model.RulePhaseResponse, Action: model.RuleActionSpec{Type: model.ActionDelay, Delay: time.Millisecond}},
		},
	}
	sink := NewNull()
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	writeExtendedCONNECT(t, fr)
	if h2Field(readH2HeaderFields(t, fr, 1), ":status") != "200" {
		t.Fatal("want 200")
	}
	echoWSClient(t, fr, tlsConn)
	if px.Metrics().RuleHits(rules.ActionLateSkip) < 1 {
		t.Fatal("inner D63 200 + response drop/delay must late_skip")
	}
	f := waitWSFlow(t, sink)
	if f.WebSocket == nil || f.WebSocket.FrameCount < 1 {
		t.Fatalf("response-phase drop must not omit frames: %+v", f.WebSocket)
	}
}

func TestInterceptHTTP2ExtendedCONNECTWebsocketCopy(t *testing.T) {
	port, saw := echoTLSWebSocketOrigin(t)
	sink := NewNull()
	spec := interceptH2ExtendedSpec(t, port)
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	writeExtendedCONNECT(t, fr, hpack.HeaderField{Name: "origin", Value: "https://app.lab"})
	expectH2Status(t, fr, 1, "200")
	echoWSClient(t, fr, tlsConn)
	if saw.upgrades.Load() != 1 || saw.Origin() != "https://app.lab" {
		t.Fatalf("upgrades=%d origin=%q", saw.upgrades.Load(), saw.Origin())
	}
	f := waitWSFlow(t, sink)
	if f.WebSocket != nil && f.WebSocket.FrameCount > 0 {
		t.Fatalf("copy path must not capture frames: %+v", f.WebSocket)
	}
	if f.Method != http.MethodConnect {
		t.Fatalf("method %q", f.Method)
	}
}

func TestInterceptHTTP2ExtendedCONNECTOriginH2(t *testing.T) {
	port, saw, accepts := echoH2WebSocketOrigin(t)
	sink := NewNull()
	spec := interceptH2OriginSpec(t, port)
	spec.Protocols.HTTP2.ExtendedConnect = true
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	writeExtendedCONNECT(t, fr, hpack.HeaderField{Name: "origin", Value: "https://app.lab"})
	expectH2Status(t, fr, 1, "200")
	echoWSClient(t, fr, tlsConn)
	if saw.upgrades.Load() != 1 {
		t.Fatalf("origin upgrades %d (want CONNECT :protocol=websocket on one TCP)", saw.upgrades.Load())
	}
	if saw.Origin() != "https://app.lab" {
		t.Fatalf("origin=%q", saw.Origin())
	}
	if accepts.Load() != 1 {
		t.Fatalf("second origin TCP forbidden: accepts=%d", accepts.Load())
	}
	f := waitWSFlow(t, sink)
	if !f.Intercepted || f.Status != http.StatusOK || f.Method != http.MethodConnect {
		t.Fatalf("flow %+v", f)
	}
}

func TestInterceptHTTP2ExtendedCONNECTIdleTimeout(t *testing.T) {
	port, _ := echoTLSWebSocketOrigin(t)
	spec := interceptH2ExtendedSpec(t, port)
	spec.Proxy.Admission.IdleTimeout = 200 * time.Millisecond
	spec.Proxy.Admission.SessionTimeout = 5 * time.Second
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	// Past sessionTimeout so a client-deadline ReadFrame error cannot look like idle success.
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	writeExtendedCONNECT(t, fr)
	expectH2Status(t, fr, 1, "200")
	start := time.Now()
	deadline := start.Add(time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("unexpected read error (want RST or DATA END_STREAM): %v after %s", err, time.Since(start))
		}
		if rst, ok := f.(*http2.RSTStreamFrame); ok && rst.StreamID == 1 {
			if time.Since(start) > time.Second {
				t.Fatalf("idle RST after %s", time.Since(start))
			}
			return
		}
		if df, ok := f.(*http2.DataFrame); ok && df.StreamID == 1 && df.StreamEnded() {
			if time.Since(start) > time.Second {
				t.Fatalf("idle END_STREAM after %s", time.Since(start))
			}
			return
		}
	}
	t.Fatal("idleTimeout did not RST or DATA END_STREAM within 1s")
}

func TestInterceptHTTP2ExtendedCONNECTOriginReject(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2ExtendedSpec(t, port)
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	writeExtendedCONNECT(t, fr)
	expectH2Status(t, fr, 1, "403")
	_ = tlsConn
	if px.Metrics().Rejected("http2") != 0 {
		t.Fatal("origin 403 must not count as reason=http2")
	}
	found := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range sink.Last() {
			if f.Protocol == model.FlowProtocolWebSocket && f.Status == http.StatusForbidden {
				found = true
			}
		}
		if found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found {
		t.Fatalf("want captured 403 flow, got %+v", sink.Last())
	}
}

func TestInterceptHTTP2ExtendedCONNECTDropRule(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("drop must not reach origin")
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2ExtendedSpec(t, port)
	spec.Rules = model.RulesSpec{
		Enabled: true,
		Items: []model.RuleSpec{{
			ID:      "drop-ws",
			Enabled: true,
			Phase:   model.RulePhaseRequest,
			Match:   model.RuleMatchSpec{PathPrefix: "/ws"},
			Action:  model.RuleActionSpec{Type: model.ActionDrop, Status: 403},
		}},
	}
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	writeExtendedCONNECT(t, fr)
	expectH2Status(t, fr, 1, "403")
	_ = tlsConn
	if px.Metrics().Rejected("http2") != 0 {
		t.Fatal("request drop must not count as reason=http2")
	}
}

func TestInterceptHTTP2GETWithExtendedConnect(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2ExtendedSpec(t, port)
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	resp, err := httpsH2ViaProxy(t, px.Addr().String(), strconv.Itoa(port), "/ok", px.Authority().CertPool())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
}

func assertNoH2ConnectFlow(t *testing.T, sink *Null) {
	t.Helper()
	for _, f := range sink.Last() {
		if f.Intercepted && f.Method == http.MethodConnect {
			t.Fatalf("inner CONNECT must not capture a flow: %+v", f)
		}
		if f.Protocol == model.FlowProtocolWebSocket {
			t.Fatalf("must not capture websocket flow: %+v", f)
		}
	}
}

func expectH2Status(t *testing.T, fr *http2.Framer, id uint32, want string) {
	t.Helper()
	fields := readH2HeaderFields(t, fr, id)
	if h2Field(fields, ":status") != want {
		t.Fatalf(":status=%s want %s in %+v", h2Field(fields, ":status"), want, fields)
	}
}

func readH2HeaderFields(t *testing.T, fr *http2.Framer, id uint32) []hpack.HeaderField {
	t.Helper()
	dec := hpack.NewDecoder(4096, nil)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch hf := f.(type) {
		case *http2.HeadersFrame:
			if hf.StreamID != id {
				continue
			}
			fields, err := dec.DecodeFull(hf.HeaderBlockFragment())
			if err != nil {
				t.Fatalf("hpack: %v", err)
			}
			return fields
		case *http2.RSTStreamFrame:
			if hf.StreamID == id {
				t.Fatalf("RST %v", hf.ErrCode)
			}
		}
	}
	t.Fatal("no response HEADERS")
	return nil
}

func h2Field(fields []hpack.HeaderField, name string) string {
	for _, f := range fields {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

func readH2WebSocketFrame(t *testing.T, fr *http2.Framer, id uint32) wsx.Frame {
	t.Helper()
	var buf bytes.Buffer
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch df := f.(type) {
		case *http2.DataFrame:
			if df.StreamID != id {
				continue
			}
			buf.Write(df.Data())
			got, err := wsx.ReadFrame(bytes.NewReader(buf.Bytes()), 0)
			if err == nil {
				return got
			}
		case *http2.RSTStreamFrame:
			if df.StreamID == id {
				t.Fatalf("RST %v", df.ErrCode)
			}
		}
	}
	t.Fatal("no websocket DATA")
	return wsx.Frame{}
}

type pushOriginSaw struct {
	enablePush atomic.Uint32
	rst        atomic.Bool
}

func startH2PushOrigin(t *testing.T) (port int, saw *pushOriginSaw) {
	t.Helper()
	saw = &pushOriginSaw{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{originCert(t)},
		NextProtos:   []string{http2x.NextProtoH2},
		MinVersion:   tls.VersionTLS12,
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		tc := tls.Server(c, cfg)
		if err := tc.Handshake(); err != nil {
			return
		}
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(tc, preface); err != nil {
			return
		}
		fr := http2.NewFramer(tc, tc)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		_ = fr.WriteSettings()
		var hdr bytes.Buffer
		enc := hpack.NewEncoder(&hdr)
		encode := func(fields []hpack.HeaderField) []byte {
			hdr.Reset()
			for _, hf := range fields {
				_ = enc.WriteField(hf)
			}
			return append([]byte(nil), hdr.Bytes()...)
		}
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					_ = f.ForeachSetting(func(s http2.Setting) error {
						if s.ID == http2.SettingEnablePush {
							saw.enablePush.Store(s.Val)
						}
						return nil
					})
					_ = fr.WriteSettingsAck()
				}
			case *http2.RSTStreamFrame:
				if f.StreamID == 2 {
					saw.rst.Store(true)
				}
			case *http2.MetaHeadersFrame:
				if f.StreamID != 1 {
					continue
				}
				if err := fr.WritePushPromise(http2.PushPromiseParam{
					StreamID: 1, PromiseID: 2, EndHeaders: true,
					BlockFragment: encode([]hpack.HeaderField{
						{Name: ":method", Value: http.MethodGet},
						{Name: ":scheme", Value: "https"},
						{Name: ":authority", Value: "app.lab"},
						{Name: ":path", Value: "/style.css"},
					}),
				}); err != nil {
					return
				}
				if err := fr.WriteHeaders(http2.HeadersFrameParam{
					StreamID: 2, EndHeaders: true,
					BlockFragment: encode([]hpack.HeaderField{
						{Name: ":status", Value: "200"},
						{Name: "content-type", Value: "text/css"},
					}),
				}); err != nil {
					return
				}
				if err := fr.WriteData(2, true, []byte("pushed-body")); err != nil {
					return
				}
				if err := fr.WriteHeaders(http2.HeadersFrameParam{
					StreamID: 1, EndHeaders: true,
					BlockFragment: encode([]hpack.HeaderField{{Name: ":status", Value: "200"}}),
				}); err != nil {
					return
				}
				if err := fr.WriteData(1, true, []byte("parent-body")); err != nil {
					return
				}
			}
		}
	}()
	_, port = hostPort(t, ln.Addr().String())
	return port, saw
}

func TestInterceptHTTP2PushCapturedNotForwarded(t *testing.T) {
	port, saw := startH2PushOrigin(t)
	sink := NewNull()
	spec := interceptH2OriginSpec(t, port)
	spec.Protocols.HTTP2.CapturePush = true
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	writeH2Headers(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodGet},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "app.lab"},
		{Name: ":path", Value: "/hello"},
	}, true)
	gotParent := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !gotParent {
		_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("inner read: %v", err)
		}
		id := f.Header().StreamID
		if id != 0 && id%2 == 0 {
			t.Fatalf("inner client must not see even-stream %T id=%d", f, id)
		}
		switch f := f.(type) {
		case *http2.PushPromiseFrame:
			t.Fatalf("inner client must not see PUSH_PROMISE (promised=%d)", f.PromiseID)
		case *http2.HeadersFrame, *http2.MetaHeadersFrame:
			if id == 1 {
				gotParent = true
			}
		case *http2.DataFrame:
			if f.StreamID == 1 && string(f.Data()) != "parent-body" && len(f.Data()) > 0 {
				t.Fatalf("inner data %q", f.Data())
			}
			if f.StreamID == 1 && f.StreamEnded() {
				gotParent = true
			}
		}
	}
	if saw.enablePush.Load() != 1 {
		t.Fatalf("origin ENABLE_PUSH=%d want 1", saw.enablePush.Load())
	}
	deadline = time.Now().Add(3 * time.Second)
	var pushed *model.Flow
	for time.Now().Before(deadline) {
		for _, f := range sink.Last() {
			if f.HTTP2 != nil && f.HTTP2.Pushed {
				pushed = f
			}
		}
		if pushed != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pushed == nil {
		t.Fatalf("promised flow not stored: %+v", sink.Last())
	}
	if pushed.HTTP2.ParentStreamID != 1 || pushed.HTTP2.PromisedID != 2 || string(pushed.Response.Body) != "pushed-body" {
		t.Fatalf("pushed %+v http2=%+v body=%q", pushed, pushed.HTTP2, pushed.Response.Body)
	}
	if px.Metrics().H2PushCaptured("ok") < 1 {
		t.Fatalf("metric ok=%d", px.Metrics().H2PushCaptured("ok"))
	}
}

func TestInterceptHTTP2PushRSTWhenCaptureOff(t *testing.T) {
	port, saw := startH2PushOrigin(t)
	sink := NewNull()
	spec := interceptH2OriginSpec(t, port)
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	resp, err := httpsH2ViaProxy(t, px.Addr().String(), strconv.Itoa(port), "/hello", px.Authority().CertPool())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "parent-body" {
		t.Fatalf("parent status=%d body=%q", resp.StatusCode, body)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !saw.rst.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	if saw.enablePush.Load() != 0 {
		t.Fatalf("origin ENABLE_PUSH=%d want 0", saw.enablePush.Load())
	}
	if !saw.rst.Load() {
		t.Fatal("origin must see RST of promised id when capturePush is false")
	}
	for _, f := range sink.Last() {
		if f.HTTP2 != nil && f.HTTP2.Pushed {
			t.Fatalf("must not store pushed flow: %+v", f)
		}
	}
	if px.Metrics().H2PushCaptured("rst") < 1 {
		t.Fatalf("metric rst=%d", px.Metrics().H2PushCaptured("rst"))
	}
}

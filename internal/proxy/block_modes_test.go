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
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
	"github.com/hilather/go-lab-mitmproxy/internal/rules"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
	"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm"
	"golang.org/x/net/http2"
)

func isConnReset(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) && errors.Is(op.Err, syscall.ECONNRESET) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection reset")
}

func readSilentClose(t *testing.T, r io.Reader, wantRST bool) {
	t.Helper()
	buf := make([]byte, 128)
	n, err := r.Read(buf)
	if n > 0 && bytes.Contains(buf[:n], []byte("HTTP/")) {
		t.Fatalf("unexpected HTTP bytes %q", buf[:n])
	}
	if wantRST {
		if !isConnReset(err) {
			t.Fatalf("want RST, got n=%d err=%v data=%q", n, err, buf[:n])
		}
		return
	}
	if isConnReset(err) {
		t.Fatalf("want FIN/EOF, got RST: %v", err)
	}
	if err == nil {
		t.Fatalf("want FIN/EOF, got n=%d data=%q", n, buf[:n])
	}
	if !errors.Is(err, io.EOF) && !strings.Contains(strings.ToLower(err.Error()), "eof") {
		t.Fatalf("want FIN/EOF, got n=%d err=%v", n, err)
	}
}

func writeAbsolute(t *testing.T, proxyAddr, originURL, method, path, body string) *proxytest.Client {
	t.Helper()
	c, err := proxytest.Dial(proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	host := mustURL(t, originURL).Host
	lines := []string{method + " " + originURL + path + " HTTP/1.1", "Host: " + host}
	if body != "" {
		lines = append(lines, "Content-Length: "+strconv.Itoa(len(body)))
	}
	if err := c.WriteRequest(lines...); err != nil {
		t.Fatal(err)
	}
	if body != "" {
		if err := c.WriteRaw([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func TestRequestSilentRST(t *testing.T) {
	var originHits int
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "silent-login",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match:   model.RuleMatchSpec{PathPrefix: "/login", Method: http.MethodPost},
		Action:  model.RuleActionSpec{Type: model.ActionSilent, Silent: model.RuleSilentSpec{Close: model.SilentCloseRST}},
	})
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox)})
	raw, err := os.ReadFile(testdataProxy(t, "rule-silent-rst.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("POST")) || bytes.Contains(raw, []byte("S:")) {
		t.Fatal("silent rst transcript must be client-only")
	}
	c := writeAbsolute(t, px.Addr().String(), originURL, http.MethodPost, "/login", "pw")
	readSilentClose(t, c.Reader(), true)
	if originHits != 0 {
		t.Fatal("silent must not dial")
	}
	got := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/login"})
	if got.State != model.FlowStateCompleted || got.Error != rules.FlowErrorSilent || got.Status != 0 {
		t.Fatalf("flow %+v", got)
	}
	if len(got.RuleIDs) != 1 || got.RuleIDs[0] != "silent-login" {
		t.Fatalf("rule ids %v", got.RuleIDs)
	}
	if px.Metrics().RuleHits(model.ActionSilent) < 1 {
		t.Fatal("expected silent hit")
	}
}

func TestRequestSilentFIN(t *testing.T) {
	var originHits int
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "silent-fin",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match:   model.RuleMatchSpec{PathPrefix: "/login"},
		Action:  model.RuleActionSpec{Type: model.ActionSilent, Silent: model.RuleSilentSpec{Close: model.SilentCloseFIN}},
	})
	px := startProxy(t, Options{Spec: spec})
	c := writeAbsolute(t, px.Addr().String(), originURL, http.MethodPost, "/login", "pw")
	readSilentClose(t, c.Reader(), false)
	if originHits != 0 {
		t.Fatal("silent must not dial")
	}
}

func TestRequestHangThenSilent(t *testing.T) {
	var originHits int
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "hang-login",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match:   model.RuleMatchSpec{PathPrefix: "/login"},
		Action: model.RuleActionSpec{
			Type: model.ActionHang,
			Hang: model.RuleHangSpec{Timeout: time.Second, Close: model.SilentCloseRST},
		},
	})
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox)})
	start := time.Now()
	c := writeAbsolute(t, px.Addr().String(), originURL, http.MethodGet, "/login", "")
	readSilentClose(t, c.Reader(), true)
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Fatalf("hang too short %s", elapsed)
	}
	if originHits != 0 {
		t.Fatal("hang must not dial")
	}
	got := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/login"})
	if got.State != model.FlowStateCompleted || got.Error != rules.FlowErrorHang || got.Status != 0 {
		t.Fatalf("flow %+v", got)
	}
}

func TestRequestRedirect(t *testing.T) {
	var originHits int
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "redir",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match:   model.RuleMatchSpec{PathPrefix: "/login"},
		Action: model.RuleActionSpec{
			Type:     model.ActionRedirect,
			Redirect: model.RuleRedirectSpec{Location: "https://app.lab.test/login"},
			Headers:  model.RuleHeadersSpec{Set: map[string]string{"Location": "https://other.test/"}},
		},
	})
	px := startProxy(t, Options{Spec: spec})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "rule-redirect.txt"), map[string]string{
		"HOST": mustURL(t, originURL).Host,
	})
	resp := proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/login", "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://app.lab.test/login" {
		t.Fatalf("Location %q (redirect.location must win)", loc)
	}
	if originHits != 0 {
		t.Fatal("redirect must not dial")
	}
}

func TestFirstMatchSilentBeatsStatus(t *testing.T) {
	var originHits int
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
	}))
	spec := withRules(t,
		model.RuleSpec{ID: "silent-first", Enabled: true, Phase: model.RulePhaseRequest, Match: model.RuleMatchSpec{PathPrefix: "/"}, Action: model.RuleActionSpec{Type: model.ActionSilent}},
		model.RuleSpec{ID: "status-second", Enabled: true, Phase: model.RulePhaseRequest, Action: model.RuleActionSpec{Type: model.ActionStatus, Status: 418}},
	)
	px := startProxy(t, Options{Spec: spec})
	c := writeAbsolute(t, px.Addr().String(), originURL, http.MethodGet, "/z", "")
	readSilentClose(t, c.Reader(), true)
	if originHits != 0 {
		t.Fatal("second rule must not run")
	}
	if px.Metrics().RuleHits(model.ActionStatus) != 0 {
		t.Fatal("status must not fire")
	}
	if px.Metrics().RuleHits(model.ActionSilent) < 1 {
		t.Fatal("expected silent")
	}
}

func TestResponseSilentAndRedirect(t *testing.T) {
	t.Run("silent", func(t *testing.T) {
		_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "secret")
		}))
		spec := withRules(t, model.RuleSpec{
			ID:      "silent-resp",
			Enabled: true,
			Phase:   model.RulePhaseResponse,
			Action:  model.RuleActionSpec{Type: model.ActionSilent},
		})
		inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
		px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox)})
		c := writeAbsolute(t, px.Addr().String(), originURL, http.MethodGet, "/r", "")
		readSilentClose(t, c.Reader(), true)
		got := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/r"})
		if got.State != model.FlowStateCompleted || got.Error != rules.FlowErrorSilent || got.Status != 0 {
			t.Fatalf("flow %+v", got)
		}
	})
	t.Run("redirect", func(t *testing.T) {
		_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "ok")
		}))
		spec := withRules(t, model.RuleSpec{
			ID:      "redir-resp",
			Enabled: true,
			Phase:   model.RulePhaseResponse,
			Action:  model.RuleActionSpec{Type: model.ActionRedirect, Redirect: model.RuleRedirectSpec{Location: "/next", Status: 307}},
		})
		px := startProxy(t, Options{Spec: spec})
		resp := proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/r", "")
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusTemporaryRedirect || resp.Header.Get("Location") != "/next" {
			t.Fatalf("status %d loc %q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})
}

func TestRulesDisabledSilentNoOp(t *testing.T) {
	var originHits int
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		_, _ = io.WriteString(w, "ok")
	}))
	spec := loadSpec(t)
	spec.Rules = model.RulesSpec{
		Enabled: false,
		Items: []model.RuleSpec{{
			ID:      "silent-off",
			Enabled: true,
			Phase:   model.RulePhaseRequest,
			Action:  model.RuleActionSpec{Type: model.ActionSilent},
		}},
	}
	px := startProxy(t, Options{Spec: spec})
	if via := throughProxy(t, px.Addr().String(), originURL+"/x"); via != "ok" {
		t.Fatalf("body %q", via)
	}
	if originHits != 1 {
		t.Fatalf("origin hits %d", originHits)
	}
	if px.Metrics().RuleHits(model.ActionSilent) != 0 {
		t.Fatal("disabled rules must not hit")
	}
}

func TestWebSocketResponseSilentLateSkip(t *testing.T) {
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
	spec := withRules(t, model.RuleSpec{
		ID:      "silent-ws",
		Enabled: true,
		Phase:   model.RulePhaseResponse,
		Action:  model.RuleActionSpec{Type: model.ActionSilent},
	})
	px := startProxy(t, Options{Spec: spec})
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
	if px.Metrics().RuleHits(rules.ActionLateSkip) < 1 {
		t.Fatal("expected late_skip")
	}
	if px.Metrics().RuleHits(model.ActionSilent) != 0 {
		t.Fatal("101 must not count the skipped silent action")
	}
}

func TestOrigDestSilentHijacks(t *testing.T) {
	var originHits int
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
	}))
	ip, port := originIPPort(t, origin)
	spec := withRules(t, model.RuleSpec{
		ID:      "silent-od",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match:   model.RuleMatchSpec{PathPrefix: "/login"},
		Action:  model.RuleActionSpec{Type: model.ActionSilent},
	})
	px := startOrigDestProxy(t, ip, port, Options{Spec: spec})
	c := writeOrigHTTP(t, px.OrigDestAddr().String(),
		"POST /login HTTP/1.1\r\nHost: app.lab\r\nContent-Length: 2\r\nConnection: close\r\n\r\npw")
	defer func() { _ = c.Close() }()
	readSilentClose(t, c, true)
	if originHits != 0 {
		t.Fatal("orig-dest silent must not dial")
	}
}

func interceptH1TLS(t *testing.T, proxyAddr, originPort string, roots *x509.CertPool) *tls.Conn {
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
		NextProtos: []string{tlsmitm.ALPN},
		MinVersion: tls.VersionTLS12,
	})
	t.Cleanup(func() { _ = tlsConn.Close() })
	_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tlsConn
}

func TestInterceptHTTP1SilentRSTAndFIN(t *testing.T) {
	for _, tc := range []struct {
		name    string
		close   string
		wantRST bool
	}{
		{"rst", model.SilentCloseRST, true},
		{"fin", model.SilentCloseFIN, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var originHits atomic.Int32
			origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				originHits.Add(1)
			}))
			_, port := hostPort(t, origin)
			spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
			spec.Rules = model.RulesSpec{
				Enabled: true,
				Items: []model.RuleSpec{{
					ID:      "silent-inner",
					Enabled: true,
					Phase:   model.RulePhaseRequest,
					Match:   model.RuleMatchSpec{PathPrefix: "/deny"},
					Action:  model.RuleActionSpec{Type: model.ActionSilent, Silent: model.RuleSilentSpec{Close: tc.close}},
				}},
			}
			inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
			px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Resolver: appLabResolver()})
			tlsConn := interceptH1TLS(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
			if _, err := io.WriteString(tlsConn, "GET /deny HTTP/1.1\r\nHost: app.lab\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			readSilentClose(t, tlsConn, tc.wantRST)
			if originHits.Load() != 0 {
				t.Fatal("inner silent must not dial origin")
			}
			got := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/deny"})
			if got.State != model.FlowStateCompleted || got.Error != rules.FlowErrorSilent || got.Status != 0 {
				t.Fatalf("flow %+v", got)
			}
		})
	}
}

func TestInterceptHTTP2SilentKeepsSibling(t *testing.T) {
	var originHits atomic.Int32
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2Spec(t, port)
	spec.Rules = model.RulesSpec{
		Enabled: true,
		Items: []model.RuleSpec{{
			ID:      "silent-login",
			Enabled: true,
			Phase:   model.RulePhaseRequest,
			Match:   model.RuleMatchSpec{PathPrefix: "/login"},
			Action:  model.RuleActionSpec{Type: model.ActionSilent},
		}},
	}
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cc.RoundTrip(req)
	if err == nil {
		t.Fatal("expected RST CANCEL, not 502 HEADERS")
	}
	if ctx.Err() != nil {
		t.Fatalf("timed out: %v", err)
	}
	okReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/ok", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(okReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("sibling status %d body %q", resp.StatusCode, body)
	}
	if originHits.Load() != 1 {
		t.Fatalf("origin hits %d", originHits.Load())
	}
	got := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/login"})
	if got.State != model.FlowStateCompleted || got.Error != rules.FlowErrorSilent {
		t.Fatalf("flow %+v", got)
	}
}

func TestInterceptHTTP2ResponseSilent(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "secret")
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2Spec(t, port)
	spec.Rules = model.RulesSpec{
		Enabled: true,
		Items: []model.RuleSpec{{
			ID:      "silent-resp",
			Enabled: true,
			Phase:   model.RulePhaseResponse,
			Action:  model.RuleActionSpec{Type: model.ActionSilent},
		}},
	}
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/r", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected RST, got status %d body %q", resp.StatusCode, b)
	}
}

func TestInterceptHTTP2HangDoesNotHoldOriginMutex(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2Spec(t, port)
	spec.Rules = model.RulesSpec{
		Enabled: true,
		Items: []model.RuleSpec{{
			ID:      "hang-slow",
			Enabled: true,
			Phase:   model.RulePhaseRequest,
			Match:   model.RuleMatchSpec{PathPrefix: "/hang"},
			Action:  model.RuleActionSpec{Type: model.ActionHang, Hang: model.RuleHangSpec{Timeout: time.Second}},
		}},
	}
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hangReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/hang", nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = cc.RoundTrip(hangReq)
	}()
	time.Sleep(80 * time.Millisecond)
	start := time.Now()
	okReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/ok", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(okReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if time.Since(start) > 700*time.Millisecond {
		t.Fatalf("second stream blocked by hang %s (D44 mutex must not be held)", time.Since(start))
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	wg.Wait()
}

func TestH2CSilentRequestAndResponse(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		var originHits int
		_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			originHits++
		}))
		spec := withRules(t, model.RuleSpec{
			ID:      "silent-h2c",
			Enabled: true,
			Phase:   model.RulePhaseRequest,
			Match:   model.RuleMatchSpec{PathPrefix: "/login"},
			Action:  model.RuleActionSpec{Type: model.ActionSilent},
		})
		spec.Protocols.HTTP2.ClientCleartext = true
		px := startProxy(t, Options{Spec: spec})
		cc := dialH2C(t, px.Addr().String())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, originURL+"/login", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := cc.RoundTrip(req)
		if err == nil {
			defer func() { _ = resp.Body.Close() }()
			t.Fatalf("expected RST, got status %d (captureRW must not synthesize 500)", resp.StatusCode)
		}
		if originHits != 0 {
			t.Fatal("h2c silent must not dial")
		}
	})
	t.Run("response", func(t *testing.T) {
		_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "secret")
		}))
		spec := withRules(t, model.RuleSpec{
			ID:      "silent-h2c-resp",
			Enabled: true,
			Phase:   model.RulePhaseResponse,
			Action:  model.RuleActionSpec{Type: model.ActionSilent},
		})
		spec.Protocols.HTTP2.ClientCleartext = true
		px := startProxy(t, Options{Spec: spec})
		cc := dialH2C(t, px.Addr().String())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, originURL+"/r", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := cc.RoundTrip(req)
		if err == nil {
			defer func() { _ = resp.Body.Close() }()
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected RST, got status %d body %q", resp.StatusCode, b)
		}
	})
}

func TestH2COrigDestSilent(t *testing.T) {
	requireOrigDest(t)
	var originHits int
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
	}))
	ip, port := originIPPort(t, origin)
	spec := withRules(t, model.RuleSpec{
		ID:      "silent-od-h2c",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match:   model.RuleMatchSpec{PathPrefix: "/login"},
		Action:  model.RuleActionSpec{Type: model.ActionSilent},
	})
	spec.Protocols.HTTP2.ClientCleartext = true
	px := startOrigDestProxy(t, ip, port, Options{Spec: spec})
	cc := dialH2C(t, px.OrigDestAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://app.lab/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		t.Fatalf("expected RST, got status %d", resp.StatusCode)
	}
	if originHits != 0 {
		t.Fatal("orig-dest-on-h2c silent must not dial")
	}
}

func TestInterceptHTTP2ExtendedCONNECTSilent(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("silent must not reach origin")
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2ExtendedSpec(t, port)
	spec.Rules = model.RulesSpec{
		Enabled: true,
		Items: []model.RuleSpec{{
			ID:      "silent-ws",
			Enabled: true,
			Phase:   model.RulePhaseRequest,
			Match:   model.RuleMatchSpec{PathPrefix: "/ws"},
			Action:  model.RuleActionSpec{Type: model.ActionSilent},
		}},
	}
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Resolver: appLabResolver()})
	fr, tlsConn := h2RawClientViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	writeExtendedCONNECT(t, fr)
	expectRSTStream(t, fr, 1, http2.ErrCodeCancel)
	_ = tlsConn
	got := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/ws"})
	if got.State != model.FlowStateCompleted || got.Error != rules.FlowErrorSilent {
		t.Fatalf("flow %+v", got)
	}
}

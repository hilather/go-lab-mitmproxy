package proxy

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/rules"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

func withRules(t *testing.T, items ...model.RuleSpec) model.Spec {
	t.Helper()
	spec := loadSpec(t)
	spec.Rules = model.RulesSpec{Enabled: true, Items: items}
	return spec
}

func item(id, phase, typ string) model.RuleSpec {
	return model.RuleSpec{ID: id, Enabled: true, Phase: phase, Action: model.RuleActionSpec{Type: typ}}
}

func TestRulesDisabledByDefault(t *testing.T) {
	var originHits int
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		_, _ = io.WriteString(w, "ok")
	}))
	spec := loadSpec(t)
	spec.Rules = model.RulesSpec{
		Enabled: false,
		Items:   []model.RuleSpec{item("drop-all", model.RulePhaseRequest, model.ActionDrop)},
	}
	px := startProxy(t, Options{Spec: spec})
	if via := throughProxy(t, px.Addr().String(), originURL+"/x"); via != "ok" {
		t.Fatalf("body %q", via)
	}
	if originHits != 1 {
		t.Fatalf("origin hits %d", originHits)
	}
	if px.Metrics().RuleHits(model.ActionDrop) != 0 {
		t.Fatal("disabled rules must not hit")
	}
}

func TestRequestDrop(t *testing.T) {
	var originHits int
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		_, _ = io.WriteString(w, "nope")
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "drop-login",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match:   model.RuleMatchSpec{PathPrefix: "/login", Method: http.MethodPost},
		Action:  model.RuleActionSpec{Type: model.ActionDrop, Status: 403, Headers: model.RuleHeadersSpec{Set: map[string]string{"X-Blocked": "1"}}},
	})
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox)})
	resp := proxyDo(t, px.Addr().String(), http.MethodPost, originURL+"/login", "pw")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Blocked") != "1" {
		t.Fatalf("headers %v", resp.Header)
	}
	if originHits != 0 {
		t.Fatal("drop must not dial")
	}
	got := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/login"})
	if got.Status != 403 || len(got.RuleIDs) != 1 || got.RuleIDs[0] != "drop-login" {
		t.Fatalf("flow %+v", got)
	}
}

func TestRequestStatusSynthesizes(t *testing.T) {
	var originHits int
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "inject",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match:   model.RuleMatchSpec{PathExact: "/fail"},
		Action:  model.RuleActionSpec{Type: model.ActionStatus, Status: 503, Body: model.RuleBodySpec{Replace: "down"}},
	})
	px := startProxy(t, Options{Spec: spec})
	resp := proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/fail", "")
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable || string(b) != "down" {
		t.Fatalf("status %d body %q", resp.StatusCode, b)
	}
	if originHits != 0 {
		t.Fatal("status must not dial")
	}
}

func TestRequestHeaderAndBody(t *testing.T) {
	var saw http.Header
	var body string
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		_, _ = io.WriteString(w, "ok")
	}))
	spec := withRules(t,
		model.RuleSpec{
			ID:      "hdr",
			Enabled: true,
			Phase:   model.RulePhaseRequest,
			Match:   model.RuleMatchSpec{PathPrefix: "/p"},
			Action: model.RuleActionSpec{
				Type:    model.ActionHeader,
				Headers: model.RuleHeadersSpec{Set: map[string]string{"X-Lab": "1"}, Remove: []string{"X-Secret"}},
			},
		},
	)
	px := startProxy(t, Options{Spec: spec})
	req, err := http.NewRequest(http.MethodPost, originURL+"/p", strings.NewReader("orig"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Secret", "no")
	tr := proxyTransport(t, px.Addr().String())
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if saw.Get("X-Lab") != "1" || saw.Get("X-Secret") != "" {
		t.Fatalf("origin headers %v", saw)
	}
	if body != "orig" {
		t.Fatalf("header action must not replace body: %q", body)
	}

	spec = withRules(t, model.RuleSpec{
		ID:      "bod",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match:   model.RuleMatchSpec{PathPrefix: "/p"},
		Action:  model.RuleActionSpec{Type: model.ActionBody, Body: model.RuleBodySpec{Replace: "rewritten"}},
	})
	px = startProxy(t, Options{Spec: spec})
	req, _ = http.NewRequest(http.MethodPost, originURL+"/p", strings.NewReader("orig"))
	tr = proxyTransport(t, px.Addr().String())
	defer tr.CloseIdleConnections()
	resp, err = tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if body != "rewritten" {
		t.Fatalf("body %q", body)
	}
}

func TestRequestDelay(t *testing.T) {
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "slow",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Action:  model.RuleActionSpec{Type: model.ActionDelay, Delay: 40 * time.Millisecond},
	})
	px := startProxy(t, Options{Spec: spec})
	start := time.Now()
	if via := throughProxy(t, px.Addr().String(), originURL+"/"); via != "ok" {
		t.Fatalf("body %q", via)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Fatalf("delay too short %s", time.Since(start))
	}
	if px.Metrics().RuleHits(model.ActionDelay) < 1 {
		t.Fatal("expected delay hit")
	}
}

func TestResponseStatusHeaderBody(t *testing.T) {
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "origin-body")
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "rewrite-resp",
		Enabled: true,
		Phase:   model.RulePhaseResponse,
		Match:   model.RuleMatchSpec{PathPrefix: "/r"},
		Action: model.RuleActionSpec{
			Type:    model.ActionStatus,
			Status:  451,
			Headers: model.RuleHeadersSpec{Set: map[string]string{"X-Lab": "r"}, Remove: []string{"X-Origin"}},
			Body:    model.RuleBodySpec{Replace: "censored"},
		},
	})
	px := startProxy(t, Options{Spec: spec})
	resp := proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/r", "")
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 451 || string(b) != "censored" {
		t.Fatalf("status %d body %q", resp.StatusCode, b)
	}
	if resp.Header.Get("X-Lab") != "r" || resp.Header.Get("X-Origin") != "" {
		t.Fatalf("headers %v", resp.Header)
	}
}

func TestResponseDrop(t *testing.T) {
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "secret")
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "drop-resp",
		Enabled: true,
		Phase:   model.RulePhaseResponse,
		Action:  model.RuleActionSpec{Type: model.ActionDrop, Status: 502},
	})
	px := startProxy(t, Options{Spec: spec})
	resp := proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/", "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestBodySkippedWhenOversize(t *testing.T) {
	var got string
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		_, _ = io.WriteString(w, "ok")
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "bod",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Action:  model.RuleActionSpec{Type: model.ActionBody, Body: model.RuleBodySpec{Replace: "tiny"}},
	})
	spec.Store.MaxBodyBytes = 8
	px := startProxy(t, Options{Spec: spec})
	big := strings.Repeat("x", 32)
	req, _ := http.NewRequest(http.MethodPost, originURL+"/b", strings.NewReader(big))
	tr := proxyTransport(t, px.Addr().String())
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got != big {
		t.Fatalf("oversize must continue unmodified, origin got %q", got)
	}
	if px.Metrics().RuleHits(rules.ActionBodySkipped) < 1 {
		t.Fatal("expected body_skipped")
	}
}

func TestFirstMatchWinsProxy(t *testing.T) {
	var originHits int
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		_, _ = io.WriteString(w, "ok")
	}))
	spec := withRules(t,
		model.RuleSpec{ID: "first", Enabled: true, Phase: model.RulePhaseRequest, Match: model.RuleMatchSpec{PathPrefix: "/"}, Action: model.RuleActionSpec{Type: model.ActionDrop, Status: 409}},
		model.RuleSpec{ID: "second", Enabled: true, Phase: model.RulePhaseRequest, Action: model.RuleActionSpec{Type: model.ActionStatus, Status: 418}},
	)
	px := startProxy(t, Options{Spec: spec})
	resp := proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/z", "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if originHits != 0 {
		t.Fatal("second rule must not run")
	}
}

func TestBreakpointResumeHTTP(t *testing.T) {
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "after")
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "brk",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match:   model.RuleMatchSpec{PathPrefix: "/brk"},
		Action:  model.RuleActionSpec{Type: model.ActionBreakpoint, Breakpoint: model.RuleBreakpointSpec{Timeout: 5 * time.Second}},
	})
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: time.Minute})
	px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Store: inbox})

	done := make(chan *http.Response, 1)
	go func() {
		done <- proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/brk", "")
	}()
	paused := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/brk"})
	if paused.State != model.FlowStatePaused {
		t.Fatalf("state %q", paused.State)
	}
	if err := inbox.Resume(paused.ID, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-done:
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(b) != "after" {
			t.Fatalf("status %d body %q", resp.StatusCode, b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client hung")
	}
}

func TestBreakpointTimeoutContinues(t *testing.T) {
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "brk",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Action:  model.RuleActionSpec{Type: model.ActionBreakpoint, Breakpoint: model.RuleBreakpointSpec{Timeout: time.Second}},
	})
	spec.Store.MaxWait = 40 * time.Millisecond
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: 40 * time.Millisecond})
	px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Store: inbox})
	start := time.Now()
	if via := throughProxy(t, px.Addr().String(), originURL+"/t"); via != "ok" {
		t.Fatalf("timeout must continue unmodified: %q", via)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("hung past timeout")
	}
	if px.Metrics().RuleHits(rules.ActionBreakpointTO) < 1 {
		t.Fatal("expected breakpoint_timeout")
	}
}

func TestInnerRequestDrop(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin must not be hit")
	}))
	_, port := hostPort(t, origin)
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	spec.Rules = model.RulesSpec{
		Enabled: true,
		Items: []model.RuleSpec{{
			ID:      "drop-inner",
			Enabled: true,
			Phase:   model.RulePhaseRequest,
			Match:   model.RuleMatchSpec{PathPrefix: "/deny"},
			Action:  model.RuleActionSpec{Type: model.ActionDrop, Status: 403},
		}},
	}
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	auth := px.Authority()
	resp, err := httpsViaProxy(t, px.Addr().String(), strconv.Itoa(port), "/deny", auth.CertPool())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func proxyTransport(t *testing.T, proxyAddr string) *http.Transport {
	t.Helper()
	return &http.Transport{
		Proxy:             http.ProxyURL(mustURL(t, "http://"+proxyAddr)),
		ForceAttemptHTTP2: false,
	}
}

func proxyDo(t *testing.T, proxyAddr, method, target, body string) *http.Response {
	t.Helper()
	tr := proxyTransport(t, proxyAddr)
	t.Cleanup(tr.CloseIdleConnections)
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, target, rdr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestSleepDelayCancelled(t *testing.T) {
	s := &Server{ctx: context.Background(), metrics: newMetrics()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.sleepDelay(ctx, time.Second) {
		t.Fatal("cancelled ctx must not sleep")
	}
}

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
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

func TestProtocolH2DropDoesNotMatchHTTP11(t *testing.T) {
	var originHits int
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		_, _ = io.WriteString(w, "ok")
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "drop-h2",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match:   model.RuleMatchSpec{Protocol: model.FlowProtocolHTTP2},
		Action:  model.RuleActionSpec{Type: model.ActionDrop, Status: 403},
	})
	px := startProxy(t, Options{Spec: spec})
	if via := throughProxy(t, px.Addr().String(), originURL+"/x"); via != "ok" {
		t.Fatalf("body %q", via)
	}
	if originHits != 1 {
		t.Fatalf("origin hits %d", originHits)
	}
	if px.Metrics().RuleHits(model.ActionDrop) != 0 {
		t.Fatal("protocol: h2 must not match HTTP/1.1")
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
	list, err := inbox.List(model.ListQuery{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("want 1 row after timeout, got %d", len(list.Items))
	}
	got := list.Items[0]
	if got.State == model.FlowStatePaused {
		t.Fatal("timeout must not leave State=paused")
	}
	if err := inbox.Resume(got.ID, nil); !errors.Is(err, store.ErrBreakpointInactive) {
		t.Fatalf("late Resume after timeout: %v", err)
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

func TestDelayDoesNotStealUpstreamBudget(t *testing.T) {
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(40 * time.Millisecond)
		_, _ = io.WriteString(w, "ok")
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "slow",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Action:  model.RuleActionSpec{Type: model.ActionDelay, Delay: 80 * time.Millisecond},
	})
	spec.Proxy.Admission.UpstreamTimeout = 100 * time.Millisecond
	px := startProxy(t, Options{Spec: spec})
	resp := proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/d", "")
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(b) != "ok" {
		t.Fatalf("delay must not steal origin budget: status %d body %q", resp.StatusCode, b)
	}
}

func TestExpectResponseDrop(t *testing.T) {
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
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	host := mustURL(t, originURL).Host
	msg := "GET " + originURL + "/s HTTP/1.1\r\nHost: " + host + "\r\nExpect: 100-continue\r\n\r\n"
	if err := c.WriteRaw([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusContinue {
		t.Fatal("client saw 100 Continue as the final status")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d body %q", resp.StatusCode, b)
	}
	if strings.Contains(string(b), "secret") {
		t.Fatalf("origin body leaked: %q", b)
	}
}

func TestExpectRequestBodyNo100(t *testing.T) {
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
		Action:  model.RuleActionSpec{Type: model.ActionBody, Body: model.RuleBodySpec{Replace: "rewritten"}},
	})
	px := startProxy(t, Options{Spec: spec})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	host := mustURL(t, originURL).Host
	msg := "POST " + originURL + "/e HTTP/1.1\r\nHost: " + host + "\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\nping"
	if err := c.WriteRaw([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusContinue {
		t.Fatal("request body + Expect must not emit 100")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got != "rewritten" {
		t.Fatalf("origin body %q", got)
	}
}

func TestResponseBreakpointResumeDropTimeout(t *testing.T) {
	t.Run("resume", func(t *testing.T) {
		_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "orig")
		}))
		spec := withRules(t, model.RuleSpec{
			ID:      "brk",
			Enabled: true,
			Phase:   model.RulePhaseResponse,
			Match:   model.RuleMatchSpec{PathPrefix: "/rb"},
			Action:  model.RuleActionSpec{Type: model.ActionBreakpoint, Breakpoint: model.RuleBreakpointSpec{Timeout: 5 * time.Second}},
		})
		inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: time.Minute})
		px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Store: inbox})
		done := make(chan *http.Response, 1)
		go func() {
			done <- proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/rb", "")
		}()
		paused := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/rb"})
		if paused.State != model.FlowStatePaused || paused.PausedPhase != model.RulePhaseResponse {
			t.Fatalf("paused %+v", paused)
		}
		if err := inbox.Resume(paused.ID, &store.ResumePatch{Body: []byte("patched")}); err != nil {
			t.Fatal(err)
		}
		select {
		case resp := <-done:
			defer func() { _ = resp.Body.Close() }()
			b, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK || string(b) != "patched" {
				t.Fatalf("status %d body %q", resp.StatusCode, b)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("client hung")
		}
		if inbox.Stats().FlowCount != 1 {
			t.Fatalf("count=%d want 1", inbox.Stats().FlowCount)
		}
	})
	t.Run("drop", func(t *testing.T) {
		_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "orig")
		}))
		spec := withRules(t, model.RuleSpec{
			ID:      "brk",
			Enabled: true,
			Phase:   model.RulePhaseResponse,
			Action:  model.RuleActionSpec{Type: model.ActionBreakpoint, Breakpoint: model.RuleBreakpointSpec{Timeout: 5 * time.Second}},
		})
		inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: time.Minute})
		px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Store: inbox})
		done := make(chan *http.Response, 1)
		go func() {
			done <- proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/drop", "")
		}()
		paused := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/drop"})
		if err := inbox.Drop(paused.ID); err != nil {
			t.Fatal(err)
		}
		select {
		case resp := <-done:
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("status %d", resp.StatusCode)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("client hung")
		}
	})
	t.Run("timeout", func(t *testing.T) {
		_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "orig")
		}))
		spec := withRules(t, model.RuleSpec{
			ID:      "brk",
			Enabled: true,
			Phase:   model.RulePhaseResponse,
			Action:  model.RuleActionSpec{Type: model.ActionBreakpoint, Breakpoint: model.RuleBreakpointSpec{Timeout: time.Second}},
		})
		spec.Store.MaxWait = 40 * time.Millisecond
		inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: 40 * time.Millisecond})
		px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Store: inbox})
		resp := proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/to", "")
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(b) != "orig" {
			t.Fatalf("timeout must continue unmodified: %d %q", resp.StatusCode, b)
		}
		list, err := inbox.List(model.ListQuery{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(list.Items) != 1 {
			t.Fatalf("count=%d", len(list.Items))
		}
		if list.Items[0].State == model.FlowStatePaused {
			t.Fatal("still paused")
		}
		if err := inbox.Resume(list.Items[0].ID, nil); !errors.Is(err, store.ErrBreakpointInactive) {
			t.Fatalf("late Resume: %v", err)
		}
	})
}

func TestWebSocketLateSkip(t *testing.T) {
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
		_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Origin: yes\r\n\r\n")
		_ = bufrw.Flush()
		_, _ = io.Copy(io.Discard, bufrw)
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "rewrite",
		Enabled: true,
		Phase:   model.RulePhaseResponse,
		Action:  model.RuleActionSpec{Type: model.ActionBody, Body: model.RuleBodySpec{Replace: "nope"}},
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
	if px.Metrics().RuleHits(model.ActionBody) != 0 {
		t.Fatal("101 must not count the skipped action")
	}
}

func TestResponseBodySkippedWhenOversize(t *testing.T) {
	big := strings.Repeat("y", 32)
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, big)
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "bod",
		Enabled: true,
		Phase:   model.RulePhaseResponse,
		Action:  model.RuleActionSpec{Type: model.ActionBody, Body: model.RuleBodySpec{Replace: "tiny"}},
	})
	spec.Store.MaxBodyBytes = 8
	px := startProxy(t, Options{Spec: spec})
	resp := proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/big", "")
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != big {
		t.Fatalf("oversize response must continue unmodified, got %q", b)
	}
	if px.Metrics().RuleHits(rules.ActionBodySkipped) < 1 {
		t.Fatal("expected body_skipped")
	}
}

func TestBreakpointStaleEpochContinues(t *testing.T) {
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "brk",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Action:  model.RuleActionSpec{Type: model.ActionBreakpoint, Breakpoint: model.RuleBreakpointSpec{Timeout: 5 * time.Second}},
	})
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: time.Minute})
	px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Store: inbox})
	done := make(chan *http.Response, 1)
	go func() {
		done <- proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/stale", "")
	}()
	_ = waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/stale"})
	inbox.Wipe()
	select {
	case resp := <-done:
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(b) != "ok" {
			t.Fatalf("stale epoch must continue: %d %q", resp.StatusCode, b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client hung")
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

func TestResponseThrottlePacesBodyNotHeaders(t *testing.T) {
	// Live #63: 4KiB at 1KiB/s. 8KiB/s + 32KiB was too loose — net/http's
	// 4KiB bufio flushed headers mid-body (~500ms) and still passed <2s
	// without Flush after WriteHeader. A body that fits in that buffer
	// holds the status line until the handler returns (TTFH≈total≈4s).
	const bodySize = 4 << 10
	const bps = 1 << 10
	payload := bytes.Repeat([]byte("a"), bodySize)
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "slow-download",
		Enabled: true,
		Phase:   model.RulePhaseResponse,
		Match:   model.RuleMatchSpec{PathPrefix: "/big"},
		Action:  model.RuleActionSpec{Type: model.ActionThrottle, BytesPerSecond: bps},
	})
	px := startProxy(t, Options{Spec: spec})
	c := writeAbsolute(t, px.Addr().String(), originURL, http.MethodGet, "/big", "")
	_ = c.Conn.SetDeadline(time.Now().Add(15 * time.Second))
	start := time.Now()
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	headerAt := time.Since(start)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Origin") != "yes" {
		t.Fatalf("headers/status %d %v", resp.StatusCode, resp.Header)
	}
	// time_starttransfer: status line + headers on the default HTTP/1.1 hop.
	// Must be ≪ body time. No-Flush H1 fails here (TTFH≈4s).
	if headerAt >= time.Second {
		t.Fatalf("TTFH %s (status line delayed; need Flush after WriteHeader)", headerAt)
	}
	bodyStart := time.Now()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("body len %d", len(got))
	}
	if time.Since(start) < 3*time.Second {
		t.Fatalf("client elapsed %s want >= 3s (~4s at 1KiB/s; wall timers run short)", time.Since(start))
	}
	if time.Since(bodyStart) < 2*time.Second {
		t.Fatalf("body elapsed %s; throttle must pace after headers", time.Since(bodyStart))
	}
	if px.Metrics().RuleHits(model.ActionThrottle) < 1 {
		t.Fatal("expected throttle hit")
	}
}

func TestRequestThrottlePacesOriginBody(t *testing.T) {
	payload := bytes.Repeat([]byte("b"), 32<<10)
	var first, last time.Time
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first = time.Now()
		_, err := io.ReadAll(r.Body)
		last = time.Now()
		if err != nil {
			t.Errorf("origin read: %v", err)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "slow-upload",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match:   model.RuleMatchSpec{Method: http.MethodPost, PathPrefix: "/big"},
		Action:  model.RuleActionSpec{Type: model.ActionThrottle, BytesPerSecond: 8 << 10},
	})
	px := startProxy(t, Options{Spec: spec})
	resp := proxyDo(t, px.Addr().String(), http.MethodPost, originURL+"/big", string(payload))
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(b) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, b)
	}
	if first.IsZero() || last.IsZero() {
		t.Fatal("origin did not see body")
	}
	if last.Sub(first) < 3*time.Second {
		t.Fatalf("origin body span %s want >= 3s (~4s at 8KiB/s)", last.Sub(first))
	}
	if px.Metrics().RuleHits(model.ActionThrottle) < 1 {
		t.Fatal("expected throttle hit")
	}
}

func TestThrottleEmptyGETNoStall(t *testing.T) {
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "slow",
		Enabled: true,
		Phase:   model.RulePhaseResponse,
		Action:  model.RuleActionSpec{Type: model.ActionThrottle, BytesPerSecond: 256},
	})
	px := startProxy(t, Options{Spec: spec})
	start := time.Now()
	resp := proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/", "")
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)
	if time.Since(start) >= 2*time.Second {
		t.Fatalf("empty GET stalled %s", time.Since(start))
	}
	if px.Metrics().RuleHits(model.ActionThrottle) < 1 {
		t.Fatal("expected throttle hit")
	}
}

func TestWebSocketThrottleLateSkip(t *testing.T) {
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
		_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Origin: yes\r\n\r\n")
		_ = bufrw.Flush()
		_, _ = io.Copy(io.Discard, bufrw)
	}))
	spec := withRules(t, model.RuleSpec{
		ID:      "slow-ws",
		Enabled: true,
		Phase:   model.RulePhaseResponse,
		Action:  model.RuleActionSpec{Type: model.ActionThrottle, BytesPerSecond: 256},
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
	if px.Metrics().RuleHits(model.ActionThrottle) != 0 {
		t.Fatal("101 must not count throttle")
	}
}

func TestOriginRequestPreservesBodyIdentity(t *testing.T) {
	orig := &idCloser{ReadCloser: io.NopCloser(strings.NewReader("hello"))}
	req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1/p", orig)
	if err != nil {
		t.Fatal(err)
	}
	req.Body = orig
	s := &Server{}
	out, _ := s.originRequest(context.Background(), req, resolved{
		Host:     "127.0.0.1",
		Port:     "80",
		Selected: net.ParseIP("127.0.0.1"),
	}, "127.0.0.1", "80", nil, nil)
	if out == nil || out.Body == nil {
		t.Fatal("nil out")
	}
	tc, ok := out.Body.(*teeCloser)
	if !ok {
		t.Fatalf("body type %T", out.Body)
	}
	if tc.c != orig {
		t.Fatal("Clone must keep the same Body wrapper so LimitReader survives originRequest")
	}
}

type idCloser struct {
	io.ReadCloser
}

func TestSleepDelayCancelled(t *testing.T) {
	s := &Server{ctx: context.Background(), metrics: newMetrics()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.sleepDelay(ctx, time.Second) {
		t.Fatal("cancelled ctx must not sleep")
	}
}

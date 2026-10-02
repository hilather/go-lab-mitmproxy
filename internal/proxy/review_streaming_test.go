package proxy

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
	"golang.org/x/net/http2"
)

// The origin cannot reach EOF until the client has received bytes beyond the
// capture cap. Full-response buffering deadlocks this exchange deterministically.
func TestHTTP2StreamsBeforeOriginEOFWithBoundedCapture(t *testing.T) {
	for _, hop := range []string{"inner-h1", "inner-h2", "h2c"} {
		t.Run(hop, func(t *testing.T) {
			const capBytes = 1024
			prefix := "data: ready\n\n" + strings.Repeat("x", 4096)
			release := make(chan struct{})
			finish := sync.OnceFunc(func() { close(release) })
			defer finish()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Trailer", "X-Stream-End")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, prefix)
				w.(http.Flusher).Flush()
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				_, _ = io.WriteString(w, "finished")
				w.Header().Set("X-Stream-End", "complete")
			})
			inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, MaxBodyBytes: capBytes})
			var cc *http2.ClientConn
			var target string
			if hop == "h2c" {
				_, originURL := startOrigin(t, handler)
				spec := loadSpec(t)
				spec.Protocols.HTTP2.ClientCleartext = true
				spec.Store.MaxBodyBytes = capBytes
				px := startProxy(t, Options{Spec: spec, Store: inbox, Sink: AdaptStore(inbox)})
				cc = dialH2C(t, px.Addr().String())
				target = originURL + "/stream-review"
			} else {
				var origin string
				if hop == "inner-h2" {
					origin = startTLSOriginH2(t, originCert(t), handler)
				} else {
					origin = startTLSOrigin(t, originCert(t), handler)
				}
				_, port := hostPort(t, origin)
				spec := interceptH2Spec(t, port)
				spec.Protocols.HTTP2.Origin = hop == "inner-h2"
				spec.Store.MaxBodyBytes = capBytes
				px := startProxy(t, Options{Spec: spec, Store: inbox, Sink: AdaptStore(inbox), Resolver: appLabResolver()})
				cc = h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
				target = "https://app.lab/stream-review"
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := cc.RoundTrip(req)
			if err != nil {
				t.Fatalf("headers withheld until origin EOF: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			got := make([]byte, len(prefix))
			if _, err := io.ReadFull(resp.Body, got); err != nil {
				t.Fatalf("body withheld until origin EOF: %v", err)
			}
			if resp.StatusCode != http.StatusOK || string(got) != prefix {
				t.Fatalf("status=%d prefix=%q", resp.StatusCode, got)
			}
			finish()
			tail, err := io.ReadAll(resp.Body)
			if err != nil || string(tail) != "finished" {
				t.Fatalf("tail=%q error=%v", tail, err)
			}
			if hop != "h2c" && resp.Trailer.Get("X-Stream-End") != "complete" {
				t.Fatalf("response trailer lost: %v", resp.Trailer)
			}
			flow := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/stream-review"})
			if !flow.Response.Truncated || len(flow.Response.Body) != capBytes || string(flow.Response.Body) != prefix[:capBytes] {
				t.Fatalf("capture: length=%d truncated=%v", len(flow.Response.Body), flow.Response.Truncated)
			}
		})
	}
}

func TestHTTP2OversizedBreakpointResumePreservesTailAndReleasesOrigin(t *testing.T) {
	const capBytes = 1024
	body := strings.Repeat("response", 1024)
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pause-review" {
			_, _ = io.WriteString(w, body)
			return
		}
		_, _ = io.WriteString(w, "next")
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2Spec(t, port)
	spec.Store.MaxBodyBytes = capBytes
	spec.Rules = model.RulesSpec{Enabled: true, Items: []model.RuleSpec{{
		ID: "pause-review", Enabled: true, Phase: model.RulePhaseResponse,
		Match:  model.RuleMatchSpec{PathExact: "/pause-review"},
		Action: model.RuleActionSpec{Type: model.ActionBreakpoint, Breakpoint: model.RuleBreakpointSpec{Timeout: 5 * time.Second}},
	}}}
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, MaxBodyBytes: capBytes})
	px := startProxy(t, Options{Spec: spec, Store: inbox, Sink: AdaptStore(inbox), Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	type result struct {
		body string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/pause-review", nil)
		if err != nil {
			done <- result{err: err}
			return
		}
		resp, err := cc.RoundTrip(req)
		if err != nil {
			done <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		done <- result{body: string(b), err: err}
	}()
	paused := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/pause-review"})
	if paused.State != model.FlowStatePaused || !paused.Response.Truncated || len(paused.Response.Body) != capBytes {
		t.Fatalf("paused capture state=%s truncated=%v bytes=%d", paused.State, paused.Response.Truncated, len(paused.Response.Body))
	}
	if err := inbox.Resume(paused.ID, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.body != body {
			t.Fatalf("resume lost response tail: bytes=%d want=%d error=%v", len(got.body), len(body), got.err)
		}
	case <-ctx.Done():
		t.Fatal("resumed response did not complete")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/next", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("origin reservation was not released: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, err := io.ReadAll(resp.Body)
	if err != nil || string(got) != "next" {
		t.Fatalf("follow-up response=%q error=%v", got, err)
	}
}

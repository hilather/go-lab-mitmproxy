package proxy

import (
	"context"
	"github.com/hilather/go-lab-mitmproxy/internal/http2x"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestResponseStreamHeadersAndCloseReleaseProducer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, streamCtx := newResponseStream(ctx)
	sourceR, sourceW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		resp := &http.Response{StatusCode: 200, Header: make(http.Header), Body: sourceR}
		err := stream.write(resp)
		stream.finish(err)
		done <- err
	}()
	resp, err := stream.response()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.WriteString(sourceW, "first") }()
	b := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != "first" {
		t.Fatalf("body=%q", b)
	}
	_ = resp.Body.Close()
	select {
	case <-streamCtx.Done():
	case <-ctx.Done():
		t.Fatal("response Close did not cancel")
	}
	// The real origin honors request-context cancellation; model that here.
	_ = sourceW.CloseWithError(streamCtx.Err())
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("response producer did not exit")
	}
}

func TestOriginResponseBodyReleasesReservation(t *testing.T) {
	for _, closeEarly := range []bool{false, true} {
		var mu sync.Mutex
		mu.Lock()
		body := &originResponseBody{ReadCloser: io.NopCloser(strings.NewReader("body")), release: mu.Unlock}
		if closeEarly {
			_ = body.Close()
		} else {
			_, _ = io.Copy(io.Discard, body)
			_ = body.Close()
		}
		if !mu.TryLock() {
			t.Fatal("origin reservation retained")
		}
		mu.Unlock()
	}
}

func TestCaptureSnapshotDuringUpload(t *testing.T) {
	cap := &cappedWriter{max: 32}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			_, _ = cap.Write([]byte("x"))
		}
	}()
	for i := 0; i < 1000; i++ {
		snap := cap.snapshot()
		if len(snap.buf) > 32 {
			t.Fatal("capture exceeds cap")
		}
	}
	<-done
	snap := cap.snapshot()
	if len(snap.buf) != 32 || !snap.truncated {
		t.Fatalf("capture=%d truncated=%v", len(snap.buf), snap.truncated)
	}
}

func TestOversizedBreakpointExplicitReplacementMatchesStoredBody(t *testing.T) {
	const capBytes = 1024
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 4*capBytes))
	}))
	spec := withRules(t, model.RuleSpec{ID: "replace-oversized", Enabled: true, Phase: model.RulePhaseResponse, Match: model.RuleMatchSpec{PathPrefix: "/replace"}, Action: model.RuleActionSpec{Type: model.ActionBreakpoint, Breakpoint: model.RuleBreakpointSpec{Timeout: 5 * time.Second}}})
	spec.Store.MaxBodyBytes = capBytes
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, MaxBodyBytes: capBytes, MaxWait: time.Minute})
	px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Store: inbox})
	done := make(chan *http.Response, 1)
	go func() { done <- proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/replace", "") }()
	paused := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/replace"})
	if !paused.Response.Truncated {
		t.Fatal("response did not exceed capture cap")
	}
	replacement := []byte("replacement")
	if err := inbox.Resume(paused.ID, &store.ResumePatch{Body: replacement}); err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-done:
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != string(replacement) {
			t.Fatalf("wire body=%q want=%q", body, replacement)
		}
		stored, err := inbox.Get(paused.ID)
		if err != nil {
			t.Fatal(err)
		}
		if string(stored.Response.Body) != string(body) || stored.Response.Truncated {
			t.Fatalf("stored body=%q truncated=%v", stored.Response.Body, stored.Response.Truncated)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("explicit replacement did not complete")
	}
}

type streamingTestTransport func(*http.Request) (*http.Response, error)

func (f streamingTestTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type streamingTestOriginBody struct {
	io.Reader
	closed chan struct{}
	once   sync.Once
}

func (b *streamingTestOriginBody) Close() error { b.once.Do(func() { close(b.closed) }); return nil }

func TestOversizedInnerBreakpointReplacementClosesOriginalAndUnlocks(t *testing.T) {
	const capBytes = 1024
	spec := withRules(t, model.RuleSpec{ID: "replace-inner", Enabled: true, Phase: model.RulePhaseResponse, Match: model.RuleMatchSpec{PathPrefix: "/replace-inner"}, Action: model.RuleActionSpec{Type: model.ActionBreakpoint, Breakpoint: model.RuleBreakpointSpec{Timeout: 5 * time.Second}}})
	spec.Store.MaxBodyBytes = capBytes
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, MaxBodyBytes: capBytes, MaxWait: time.Minute})
	px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Store: inbox})
	source := &streamingTestOriginBody{Reader: strings.NewReader(strings.Repeat("x", 4*capBytes)), closed: make(chan struct{})}
	rt := streamingTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: source}, nil
	})
	var reservation sync.Mutex
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, _, err := px.roundTripInnerH2(ctx, rt, &reservation, nil, http2x.Stream{Method: "GET", Scheme: "https", Authority: "app.lab", Path: "/replace-inner", Body: http.NoBody}, "app.lab", "443", resolved{}, nil, px.beginSession(), false)
		if err != nil {
			done <- result{err: err}
			return
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		done <- result{body: body, err: err}
	}()
	paused := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/replace-inner"})
	replacement := []byte("replacement")
	if err := inbox.Resume(paused.ID, &store.ResumePatch{Body: replacement}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || string(got.body) != string(replacement) {
			t.Fatalf("wire=%q err=%v", got.body, got.err)
		}
	case <-ctx.Done():
		t.Fatal("replacement stalled")
	}
	select {
	case <-source.closed:
	case <-ctx.Done():
		t.Fatal("original unread body not closed")
	}
	released := make(chan struct{})
	go func() { reservation.Lock(); close(released); reservation.Unlock() }()
	select {
	case <-released:
	case <-ctx.Done():
		t.Fatal("original body reservation leaked")
	}
	stored, err := inbox.Get(paused.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored.Response.Body) != string(replacement) || stored.Response.Truncated {
		t.Fatalf("stored body=%q truncated=%v", stored.Response.Body, stored.Response.Truncated)
	}
}

package rules

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

// TestResumeWithoutHTTP is the PR 6 contract: Insert paused → WaitPaused →
// Resume with patch, no socket. Snapshot is constructed in-test (no compiler).
func TestResumeWithoutHTTP(t *testing.T) {
	eng := snapshotEngine(true, model.RuleSpec{
		ID:      "break-login",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match:   model.RuleMatchSpec{PathPrefix: "/login", Method: "POST"},
		Action: model.RuleActionSpec{
			Type:       model.ActionBreakpoint,
			Breakpoint: model.RuleBreakpointSpec{Timeout: 30 * time.Second},
		},
	})
	hit := eng.Match(model.RulePhaseRequest, Request{Host: "app.lab.test", Path: "/login", Method: "POST"})
	if hit == nil || hit.ID != "break-login" || !Mutates(hit) {
		t.Fatalf("hit %+v", hit)
	}

	inbox, err := store.New(store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inbox.Wipe)

	f := &model.Flow{
		StartedAt:   time.Now().UTC(),
		State:       model.FlowStatePaused,
		PausedPhase: model.RulePhaseRequest,
		Method:      "POST",
		URL:         "http://app.lab.test/login",
		Host:        "app.lab.test",
		Scheme:      "http",
		Protocol:    model.FlowProtocolHTTP11,
		RuleIDs:     []string{hit.ID},
		Request:     model.HTTPMessage{Body: []byte("old"), Size: 3},
	}
	res, err := inbox.Insert(context.Background(), inbox.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}

	timeout := ClampBreakpointTimeout(hit.Action.Breakpoint.Timeout, time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	errc := make(chan error, 1)
	var patch store.ResumePatch
	go func() {
		p, err := inbox.WaitPaused(ctx, res.ID)
		patch = p
		errc <- err
	}()

	want := []byte("patched")
	if err := inbox.Resume(res.ID, &store.ResumePatch{
		Headers: []model.Header{{Name: "X-Lab", Value: "1"}},
		Body:    want,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitPaused did not wake")
	}
	if !bytes.Equal(patch.Body, want) {
		t.Fatalf("patch %q", patch.Body)
	}
	got, err := inbox.Get(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != model.FlowStateOpen {
		t.Fatalf("state=%q want open (request-phase)", got.State)
	}
	if got.RuleIDs[0] != "break-login" {
		t.Fatalf("rule ids %v", got.RuleIDs)
	}
}

func TestWaitPausedTimeoutContinuesUnmodified(t *testing.T) {
	inbox, err := store.New(store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inbox.Wipe)
	f := &model.Flow{
		State:       model.FlowStatePaused,
		PausedPhase: model.RulePhaseResponse,
		Method:      "GET",
		URL:         "http://h/",
		Host:        "h",
		Request:     model.HTTPMessage{Body: []byte("keep")},
	}
	res, err := inbox.Insert(context.Background(), inbox.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	timeout := ClampBreakpointTimeout(time.Second, 20*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err = inbox.WaitPaused(ctx, res.ID)
	if err == nil {
		t.Fatal("expected ctx timeout")
	}
	got, err := inbox.Get(res.ID)
	if err != nil || got.State != model.FlowStatePaused {
		t.Fatalf("timeout must leave flow paused for unmodified continue: %+v %v", got, err)
	}
}

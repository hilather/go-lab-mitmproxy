package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestPauseResumeWaitPaused(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	f := sampleFlow("POST", "http://app.lab.test/login", 0, nil)
	f.State = model.FlowStatePaused
	f.PausedPhase = model.RulePhaseRequest
	f.Request.Body = []byte("old")
	f.Request.Size = 3
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(res.ID)
	if err != nil || got.State != model.FlowStatePaused {
		t.Fatalf("insert paused: %+v err=%v", got, err)
	}

	errc := make(chan error, 1)
	var patch ResumePatch
	go func() {
		p, err := s.WaitPaused(context.Background(), res.ID)
		patch = p
		errc <- err
	}()
	time.Sleep(15 * time.Millisecond)
	wantBody := []byte("patched")
	if err := s.Resume(res.ID, &ResumePatch{
		Headers: []model.Header{{Name: "X-Lab", Value: "1"}},
		Body:    wantBody,
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
	if !bytes.Equal(patch.Body, wantBody) {
		t.Fatalf("patch body %q", patch.Body)
	}
	if len(patch.Headers) != 1 || patch.Headers[0].Name != "X-Lab" {
		t.Fatalf("patch headers %+v", patch.Headers)
	}
	done, err := s.Get(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.State != model.FlowStateOpen {
		t.Fatalf("state=%q want open (request-phase)", done.State)
	}
	if !bytes.Equal(done.Request.Body, wantBody) {
		t.Fatalf("stored body %q", done.Request.Body)
	}
}

func TestResumeResponsePhaseCompletes(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	f := sampleFlow("GET", "http://app.lab.test/x", 200, []byte("orig"))
	f.State = model.FlowStatePaused
	f.PausedPhase = model.RulePhaseResponse
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Resume(res.ID, &ResumePatch{Body: []byte("new")}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != model.FlowStateCompleted {
		t.Fatalf("state=%q", got.State)
	}
	if string(got.Response.Body) != "new" {
		t.Fatalf("body=%q", got.Response.Body)
	}
}

func TestResumeNonPaused(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	res, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/", 200, []byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Resume(res.ID, nil); !errors.Is(err, ErrBreakpointInactive) {
		t.Fatalf("err=%v", err)
	}
}

func TestDropUnblocksWaitPaused(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	f := sampleFlow("GET", "http://h/", 0, nil)
	f.State = model.FlowStatePaused
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := s.WaitPaused(context.Background(), res.ID)
		errc <- err
	}()
	time.Sleep(15 * time.Millisecond)
	if err := s.Drop(res.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if !errors.Is(err, ErrDropped) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitPaused did not wake")
	}
	got, err := s.Get(res.ID)
	if err != nil || got.State != model.FlowStateDropped {
		t.Fatalf("got %+v err=%v", got, err)
	}
}

func TestWaitPausedWipeStaleEpoch(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	f := sampleFlow("GET", "http://h/", 0, nil)
	f.State = model.FlowStatePaused
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := s.WaitPaused(context.Background(), res.ID)
		errc <- err
	}()
	time.Sleep(15 * time.Millisecond)
	s.Wipe()
	select {
	case err := <-errc:
		if !errors.Is(err, ErrStaleEpoch) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitPaused did not cancel on wipe")
	}
}

func TestWaitPausedTimeoutInCallerCtx(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: time.Hour})
	f := sampleFlow("GET", "http://h/", 0, nil)
	f.State = model.FlowStatePaused
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = s.WaitPaused(ctx, res.ID)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatalf("store timer outlived caller ctx: %s", time.Since(start))
	}
}

func TestPauseExisting(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	res, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/", 200, []byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	g := s.Generation()
	if err := s.Pause(res.ID); err != nil {
		t.Fatal(err)
	}
	if s.Generation() <= g {
		t.Fatal("Pause must bump generation")
	}
	got, err := s.Get(res.ID)
	if err != nil || got.State != model.FlowStatePaused {
		t.Fatalf("got %+v err=%v", got, err)
	}
}

func TestDeletePausedWakesWaiter(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	f := sampleFlow("GET", "http://h/", 0, nil)
	f.State = model.FlowStatePaused
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := s.WaitPaused(context.Background(), res.ID)
		errc <- err
	}()
	time.Sleep(15 * time.Millisecond)
	if err := s.Delete(res.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitPaused did not wake on delete")
	}
}

func TestWaitPausedAfterResumeReturnsPatch(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	f := sampleFlow("POST", "http://h/login", 0, []byte("old"))
	f.State = model.FlowStatePaused
	f.PausedPhase = model.RulePhaseRequest
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("patched")
	if err := s.Resume(res.ID, &ResumePatch{Body: want}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	patch, err := s.WaitPaused(ctx, res.ID)
	if err != nil {
		t.Fatalf("late WaitPaused err=%v", err)
	}
	if !bytes.Equal(patch.Body, want) {
		t.Fatalf("patch %q", patch.Body)
	}
}

func TestWaitPausedAfterDrop(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	f := sampleFlow("GET", "http://h/", 0, nil)
	f.State = model.FlowStatePaused
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Drop(res.ID); err != nil {
		t.Fatal(err)
	}
	_, err = s.WaitPaused(context.Background(), res.ID)
	if !errors.Is(err, ErrDropped) {
		t.Fatalf("err=%v", err)
	}
}

func TestResumeEvictOldestGrowsUnderCap(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 20, FullPolicy: model.FullPolicyEvictOldest})
	old, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/old", 200, []byte("abcdefghij")))
	if err != nil {
		t.Fatal(err)
	}
	f := sampleFlow("GET", "http://h/paused", 0, []byte("ab"))
	f.State = model.FlowStatePaused
	f.PausedPhase = model.RulePhaseResponse
	paused, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	big := []byte("0123456789ABCDEF")
	if err := s.Resume(paused.ID, &ResumePatch{Body: big}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(old.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected evict of other flow: %v", err)
	}
	got, err := s.Get(paused.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Response.Body) != string(big) {
		t.Fatalf("body=%q", got.Response.Body)
	}
	if s.Stats().Bytes > 20 {
		t.Fatalf("bytes %d over cap", s.Stats().Bytes)
	}
}

func TestResumeEmptyBodyClearsSpill(t *testing.T) {
	dir := t.TempDir()
	s := newTestStore(t, Options{
		MaxFlows:       10,
		MaxBytes:       1 << 20,
		FullPolicy:     model.FullPolicyReject,
		SpillDirectory: dir,
		SpillThreshold: 8,
	})
	body := []byte("zzzzzzzzzzzz")
	f := sampleFlow("GET", "http://h/spill", 200, body)
	f.State = model.FlowStatePaused
	f.PausedPhase = model.RulePhaseResponse
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Resume(res.ID, &ResumePatch{Body: []byte{}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Response.Body) != 0 || got.Response.Size != 0 {
		t.Fatalf("empty replace resurrected body=%q size=%d", got.Response.Body, got.Response.Size)
	}
}

func TestExpireBreakpointTimeout(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	f := sampleFlow("GET", "http://h/", 0, []byte("ab"))
	f.State = model.FlowStatePaused
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ExpireBreakpoint(res.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != model.FlowStateCompleted || got.Error != "breakpoint_timeout" {
		t.Fatalf("got %+v", got)
	}
	if err := s.Resume(res.ID, nil); !errors.Is(err, ErrBreakpointInactive) {
		t.Fatalf("late Resume err=%v", err)
	}
	_, err = s.WaitPaused(context.Background(), res.ID)
	if !errors.Is(err, ErrBreakpointTimeout) {
		t.Fatalf("WaitPaused after expire: %v", err)
	}
}

func TestResumePatchOverMaxBody(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, MaxBodyBytes: 4, FullPolicy: model.FullPolicyReject})
	f := sampleFlow("GET", "http://h/", 0, []byte("ab"))
	f.State = model.FlowStatePaused
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Resume(res.ID, &ResumePatch{Body: []byte("12345")}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err=%v", err)
	}
	got, err := s.Get(res.ID)
	if err != nil || got.State != model.FlowStatePaused {
		t.Fatalf("failed resume mutated state: %+v err=%v", got, err)
	}
}

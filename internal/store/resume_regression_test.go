package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestResumeSpilledBodyReplacementPreservesNewFile(t *testing.T) {
	for _, phase := range []string{model.RulePhaseRequest, model.RulePhaseResponse} {
		t.Run(string(phase), func(t *testing.T) {
			dir := t.TempDir()
			s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, MaxBodyBytes: 4096, FullPolicy: model.FullPolicyReject, SpillDirectory: dir, SpillThreshold: 8})
			f := sampleFlow("POST", "http://lab/a", 200, bytes.Repeat([]byte("r"), 32))
			f.Request.Body = bytes.Repeat([]byte("q"), 32)
			f.Request.Size = 32
			f.State = model.FlowStatePaused
			f.PausedPhase = phase
			res, err := s.Insert(context.Background(), s.Epoch(), f)
			if err != nil {
				t.Fatal(err)
			}
			patch := bytes.Repeat([]byte("n"), 64)
			if err := s.Resume(res.ID, &ResumePatch{Body: patch}); err != nil {
				t.Fatal(err)
			}
			got, err := s.Get(res.ID)
			if err != nil {
				t.Fatal(err)
			}
			side := "req"
			body := got.Request.Body
			if phase == model.RulePhaseResponse {
				side = "resp"
				body = got.Response.Body
			}
			if !bytes.Equal(body, patch) {
				t.Fatalf("patched body %q", body)
			}
			raw, err := os.ReadFile(filepath.Join(dir, res.ID+"-"+side+".body"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, patch) {
				t.Fatal("new spill file does not hold patch")
			}
			files, _ := os.ReadDir(dir)
			if len(files) != 2 {
				t.Fatalf("leftover staged files: %v", files)
			}
		})
	}
}
func TestRejectedResumePreservesSpillBodyAndAccounting(t *testing.T) {
	dir := t.TempDir()
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, MaxBodyBytes: 4096, FullPolicy: model.FullPolicyReject, SpillDirectory: dir, SpillThreshold: 8})
	f := sampleFlow("GET", "http://lab/a", 200, bytes.Repeat([]byte("o"), 32))
	f.State = model.FlowStatePaused
	f.PausedPhase = model.RulePhaseResponse
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://lab/b", 200, bytes.Repeat([]byte("x"), 100))); err != nil {
		t.Fatal(err)
	}
	before := s.Stats()
	s.maxBytes = before.Bytes
	if err := s.Resume(res.ID, &ResumePatch{Body: bytes.Repeat([]byte("n"), 64)}); !errors.Is(err, ErrFull) {
		t.Fatalf("want ErrFull, got %v", err)
	}
	got, err := s.Get(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Response.Body, f.Response.Body) || got.State != model.FlowStatePaused || s.Stats() != before {
		t.Fatal("rejected patch changed stored body, state, or counters")
	}
	if files, _ := os.ReadDir(dir); len(files) != 2 {
		t.Fatalf("leftover staged files: %v", files)
	}
}
func TestResumeExplicitEmptyBodyAndHeadersStayNonNil(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	f := sampleFlow("GET", "http://lab/a", 200, []byte("old"))
	f.State = model.FlowStatePaused
	f.PausedPhase = model.RulePhaseResponse
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Resume(res.ID, &ResumePatch{Body: []byte{}, Headers: []model.Header{}}); err != nil {
		t.Fatal(err)
	}
	patch, err := s.WaitPaused(context.Background(), res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if patch.Body == nil || patch.Headers == nil {
		t.Fatal("explicit empty replacement collapsed to nil (keep)")
	}
	got, err := s.Get(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Response.Body == nil || got.Response.Headers == nil || len(got.Response.Body) != 0 || len(got.Response.Headers) != 0 {
		t.Fatal("stored empty replacement collapsed to nil")
	}
}

func TestResumeSpillCommitFailureDoesNotEvictOrChangeOriginal(t *testing.T) {
	dir := t.TempDir()
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, MaxBodyBytes: 4096, FullPolicy: model.FullPolicyEvictOldest, SpillDirectory: dir, SpillThreshold: 8})
	f := sampleFlow("GET", "http://lab/a", 200, bytes.Repeat([]byte("o"), 32))
	f.State = model.FlowStatePaused
	f.PausedPhase = model.RulePhaseResponse
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://lab/b", 200, bytes.Repeat([]byte("x"), 100)))
	if err != nil {
		t.Fatal(err)
	}
	before := s.Stats()
	s.maxBytes = before.Bytes
	nextDir := t.TempDir()
	s.spillDir = nextDir
	if err := os.Mkdir(filepath.Join(nextDir, res.ID+"-resp.body"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Resume(res.ID, &ResumePatch{Body: bytes.Repeat([]byte("n"), 64)}); !errors.Is(err, ErrSpill) {
		t.Fatalf("want ErrSpill, got %v", err)
	}
	got, err := s.Get(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Response.Body, f.Response.Body) || got.State != model.FlowStatePaused || s.Stats() != before {
		t.Fatal("failed spill commit changed old body or counters")
	}
	if _, err := s.Get(other.ID); err != nil {
		t.Fatal("failed spill commit evicted another flow")
	}
	files, _ := os.ReadDir(nextDir)
	if len(files) != 1 {
		t.Fatalf("staged file leaked: %v", files)
	}
}
func TestResumeUntouchedTruncatedBodyIsNotReplacement(t *testing.T) {
	for _, headersOnly := range []bool{false, true} {
		t.Run(fmt.Sprint(headersOnly), func(t *testing.T) {
			s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, MaxBodyBytes: 8, FullPolicy: model.FullPolicyReject})
			f := sampleFlow("GET", "http://lab/a", 200, []byte("long-original-body"))
			f.State = model.FlowStatePaused
			f.PausedPhase = model.RulePhaseResponse
			res, err := s.Insert(context.Background(), s.Epoch(), f)
			if err != nil {
				t.Fatal(err)
			}
			var in *ResumePatch
			if headersOnly {
				in = &ResumePatch{Headers: []model.Header{{Name: "X-Resumed", Value: "true"}}}
			}
			if err := s.Resume(res.ID, in); err != nil {
				t.Fatal(err)
			}
			patch, err := s.WaitPaused(context.Background(), res.ID)
			if err != nil {
				t.Fatal(err)
			}
			if patch.Body != nil {
				t.Fatalf("untouched truncated capture synthesized replacement %q", patch.Body)
			}
			got, err := s.Get(res.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Response.Truncated || string(got.Response.Body) != "long-ori" {
				t.Fatal("resume changed capture prefix")
			}
		})
	}
}

package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

func TestResetWipesFlowsAndRestoresBootstrap(t *testing.T) {
	svc, boot := mustBoot(t)
	ctx := context.Background()
	id := insertRaw(t, svc, "keep-me-not.lab")
	oldEpoch := svc.Inbox().Epoch()
	oldSPKI := svc.Active().CA.Status().SPKISHA256
	applied, err := svc.Apply(ctx, actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		IdempotencyKey:   "before-reset",
		Reason:           "enable rules",
		Operations:       []model.Operation{enableRules()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !applied.Drifted {
		t.Fatal("expected drift after apply")
	}

	res, err := svc.Reset(ctx, actor(), ResetIn{Reason: "restore"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied || res.Drifted {
		t.Fatalf("reset applied=%v drifted=%v", res.Applied, res.Drifted)
	}
	live := svc.Active()
	if live.Revision != boot.Revision {
		t.Fatalf("reset rev=%s boot=%s", live.Revision, boot.Revision)
	}
	if live.Generation <= boot.Generation {
		t.Fatalf("generation %d not incremented", live.Generation)
	}
	if svc.Inbox().Epoch() == oldEpoch {
		t.Fatal("reset must bump epoch")
	}
	if svc.Inbox().Stats().FlowCount != 0 {
		t.Fatal("flows survived reset")
	}
	if _, err := svc.Inbox().Get(id); !isNotFound(err) {
		t.Fatalf("wiped id still present: %v", err)
	}
	if live.CA == nil || live.CA.Status().SPKISHA256 == oldSPKI {
		t.Fatal("reset must rotate generate-mode CA")
	}

	_, err = svc.Apply(ctx, actor(), ChangeIn{
		ExpectedRevision: live.Revision,
		IdempotencyKey:   "before-reset",
		Reason:           "after reset",
		Operations:       []model.Operation{enableRules()},
	})
	if err != nil {
		t.Fatalf("reset should have cleared idempotency: %v", err)
	}
	listed, err := svc.QueryAudit(ctx, actor(), AuditQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	foundReset := false
	for _, ev := range listed.Events {
		if ev.Capability == "state.reset" {
			foundReset = true
			if ev.Reason != "restore" {
				t.Fatalf("reset reason=%q", ev.Reason)
			}
		}
	}
	if !foundReset {
		t.Fatal("missing state.reset audit")
	}
}

func TestResetStaleInsert(t *testing.T) {
	svc, _ := mustBoot(t)
	old := svc.Inbox().Epoch()
	if _, err := svc.Reset(context.Background(), actor(), ResetIn{}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.Inbox().Insert(context.Background(), old, &model.Flow{
		Host:   "stale.lab",
		Method: "GET",
		State:  model.FlowStateCompleted,
	})
	if !isStale(err) {
		t.Fatalf("stale insert err=%v", err)
	}
	if svc.Inbox().Stats().FlowCount != 0 {
		t.Fatal("stale insert stored")
	}
}

func TestFailedResetLeavesFlowsAndSnapshot(t *testing.T) {
	svc, boot := mustBoot(t)
	ctx := context.Background()
	insertRaw(t, svc, "stay.lab")
	if _, err := svc.Apply(ctx, actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Operations:       []model.Operation{enableRules()},
	}); err != nil {
		t.Fatal(err)
	}
	live := svc.Active()
	count := svc.Inbox().Stats().FlowCount
	epoch := svc.Inbox().Epoch()
	spki := live.CA.Status().SPKISHA256
	svc.bootstrapPath = filepath.Join(t.TempDir(), "missing.yaml")
	_, err := svc.Reset(ctx, actor(), ResetIn{})
	requireCode(t, err, domainerr.CodeValidationFailed)
	if svc.Active() != live {
		t.Fatal("failed reset swapped snapshot")
	}
	if svc.Inbox().Stats().FlowCount != count || svc.Inbox().Epoch() != epoch {
		t.Fatal("failed reset must not wipe")
	}
	if svc.Active().CA.Status().SPKISHA256 != spki {
		t.Fatal("failed reset rotated CA")
	}

	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("not: valid: labmitm\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc.bootstrapPath = bad
	_, err = svc.Reset(ctx, actor(), ResetIn{})
	requireCode(t, err, domainerr.CodeValidationFailed)
	if svc.Active() != live {
		t.Fatal("invalid bootstrap reset swapped")
	}
	if svc.Inbox().Stats().FlowCount != count {
		t.Fatal("invalid reset wiped inbox")
	}
}

func TestResetBadSpillLeavesFlowsAndSnapshot(t *testing.T) {
	svc, _ := mustBoot(t)
	ctx := context.Background()
	id := insertRaw(t, svc, "stay.lab")
	live := svc.Active()
	epoch := svc.Inbox().Epoch()

	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	spill := filepath.Join(blocker, "spill")
	cfg := filepath.Join(dir, "labmitm.yaml")
	body := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: lab-proxy\nspec:\n  store:\n    spillDirectory: " + spill + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	svc.bootstrapPath = cfg

	_, err := svc.Reset(ctx, actor(), ResetIn{Reason: "bad spill"})
	if err == nil {
		t.Fatal("expected reset to fail on unwritable spill")
	}
	if svc.Active() != live {
		t.Fatal("failed reset swapped snapshot")
	}
	if svc.Inbox().Epoch() != epoch {
		t.Fatal("failed reset bumped epoch")
	}
	if _, err := svc.Inbox().Get(id); err != nil {
		t.Fatalf("flow gone after failed reset: %v", err)
	}
}

func TestResetHooksRunWithoutAppLock(t *testing.T) {
	svc, _ := mustBoot(t)
	done := make(chan struct{})
	svc.OnReset(func() {
		svc.OnReset(func() {})
		if _, err := svc.Plan(context.Background(), actor(), ChangeIn{
			ExpectedRevision: svc.Active().Revision,
			Operations:       []model.Operation{enableRules()},
		}); err != nil {
			t.Errorf("plan from reset hook: %v", err)
		}
		close(done)
	})
	if _, err := svc.Reset(context.Background(), actor(), ResetIn{Reason: "hook-unlock"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reset hook deadlocked on App.mu")
	}
}

func isNotFound(err error) bool {
	return err != nil && (err.Error() == "flow not found" || err == store.ErrNotFound)
}

func isStale(err error) bool {
	return err != nil && err == store.ErrStaleEpoch
}

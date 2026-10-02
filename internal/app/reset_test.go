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
	rolledBack := false
	svc.SetResetRuntime(func(context.Context, model.Spec) (func(), func(), error) {
		return func() { t.Error("store failure committed staged runtime") }, func() { rolledBack = true }, nil
	})

	_, err := svc.Reset(ctx, actor(), ResetIn{Reason: "bad spill"})
	if err == nil {
		t.Fatal("expected reset to fail on unwritable spill")
	}
	if !rolledBack {
		t.Fatal("store failure did not roll back runtime preflight")
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

func TestResetRuntimePreflightFailureLeavesStateAndStore(t *testing.T) {
	svc, _ := mustBoot(t)
	before := svc.Active()
	id := insertRaw(t, svc, "preserved.lab")
	epoch := svc.Inbox().Epoch()
	svc.SetResetRuntime(func(context.Context, model.Spec) (func(), func(), error) {
		return nil, nil, domainerr.Internal("listener bind failed")
	})
	if _, err := svc.Reset(context.Background(), actor(), ResetIn{Reason: "bind fails"}); err == nil {
		t.Fatal("Reset ignored runtime preflight failure")
	}
	if svc.Active() != before || svc.Inbox().Epoch() != epoch {
		t.Fatal("preflight failure changed state or store epoch")
	}
	if _, err := svc.Inbox().Get(id); err != nil {
		t.Fatalf("preflight failure lost flow: %v", err)
	}
}

func TestResetRuntimeCommitSeesNewSnapshot(t *testing.T) {
	svc, _ := mustBoot(t)
	before := svc.Active()
	var commits, rollbacks int
	svc.SetResetRuntime(func(context.Context, model.Spec) (func(), func(), error) {
		committed := false
		return func() {
				if svc.Active() == before {
					t.Error("runtime commit preceded snapshot swap")
				}
				commits++
				committed = true
			}, func() {
				if !committed {
					rollbacks++
				}
			}, nil
	})
	if _, err := svc.Reset(context.Background(), actor(), ResetIn{Reason: "commit"}); err != nil {
		t.Fatal(err)
	}
	if commits != 1 || rollbacks != 0 {
		t.Fatalf("commit=%d rollback=%d", commits, rollbacks)
	}
}

func TestResetRuntimePreflightSerializesConcurrentApply(t *testing.T) {
	svc, boot := mustBoot(t)
	changed, err := svc.Apply(context.Background(), actor(), ChangeIn{ExpectedRevision: boot.Revision, IdempotencyKey: "before-concurrent-reset", Reason: "rules", Operations: []model.Operation{enableRules()}})
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	svc.SetResetRuntime(func(context.Context, model.Spec) (func(), func(), error) {
		close(entered)
		<-release
		return func() {}, func() {}, nil
	})
	resetDone := make(chan error, 1)
	go func() {
		_, err := svc.Reset(context.Background(), actor(), ResetIn{Reason: "concurrent"})
		resetDone <- err
	}()
	<-entered
	applyDone := make(chan error, 1)
	go func() {
		_, err := svc.Apply(context.Background(), actor(), ChangeIn{ExpectedRevision: changed.RuntimeRevision, IdempotencyKey: "during-reset", Reason: "stale", Operations: []model.Operation{enableRules()}})
		applyDone <- err
	}()
	close(release)
	if err := <-resetDone; err != nil {
		t.Fatal(err)
	}
	err = <-applyDone
	de, ok := domainerr.As(err)
	if !ok || de.Code != "revision_conflict" {
		t.Fatalf("concurrent stale Apply should conflict after Reset: %v", err)
	}
	if svc.Active().Revision != boot.Revision {
		t.Fatal("concurrent Apply replaced Reset snapshot")
	}
}

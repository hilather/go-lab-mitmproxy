package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func copyDefaults(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata", "config", "valid", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "labmitm.yaml")
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustBoot(t *testing.T) (*App, *snapshot.Snapshot) {
	t.Helper()
	path := copyDefaults(t)
	svc, err := Boot(context.Background(), Options{BootstrapPath: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	snap := svc.Active()
	if snap == nil {
		t.Fatal("no snapshot")
	}
	return svc, snap
}

func actor() Actor {
	return Actor{ID: "test", Class: "test", Transport: "direct"}
}

func requireCode(t *testing.T, err error, code domainerr.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s", code)
	}
	de, ok := domainerr.As(err)
	if !ok || de.Code != code {
		t.Fatalf("err=%v want %s", err, code)
	}
}

func enableRules() model.Operation {
	return model.Operation{
		Op: model.OpReplaceRules,
		Rules: &model.RulesSpec{
			Enabled: true,
			Items:   []model.RuleSpec{},
		},
	}
}

func shrinkStore(maxFlows int, policy string) model.Operation {
	return model.Operation{
		Op: model.OpReplaceStoreCaps,
		Store: &model.StoreCaps{
			MaxFlows:     maxFlows,
			MaxBytes:     256 << 20,
			MaxBodyBytes: 1 << 20,
			FullPolicy:   policy,
		},
	}
}

func insertRaw(t *testing.T, svc *App, host string) string {
	t.Helper()
	res, err := svc.Inbox().Insert(context.Background(), svc.Inbox().Epoch(), &model.Flow{
		Host:     host,
		Method:   "GET",
		URL:      "http://" + host + "/",
		Scheme:   "http",
		Protocol: model.FlowProtocolHTTP11,
		State:    model.FlowStateCompleted,
		Status:   200,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.ID
}

package proxy

import (
	"io"
	"net/http"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/compiler"
	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
)

func TestProxyLoadsSnapshotPerRequest(t *testing.T) {
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	st, err := config.Load([]byte("apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := compiler.Compile(t.Context(), st, compiler.CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	snaps := snapshot.NewStore()
	snaps.InstallBootstrap(snap)
	px := startProxy(t, Options{Spec: snap.Canonical.Spec, Snapshots: snaps, Authority: snap.CA})
	if via := throughProxy(t, px.Addr().String(), originURL+"/x"); via != "ok" {
		t.Fatalf("body %q", via)
	}

	nextState, err := config.Load([]byte("apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	nextState.Spec.Rules = model.RulesSpec{
		Enabled: true,
		Items: []model.RuleSpec{{
			ID:      "drop-all",
			Enabled: true,
			Phase:   model.RulePhaseRequest,
			Action:  model.RuleActionSpec{Type: model.ActionDrop, Status: 403},
		}},
	}
	next, err := compiler.Compile(t.Context(), nextState, compiler.CompileOpts{Previous: snap, Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	snaps.Swap(next)
	resp := proxyDo(t, px.Addr().String(), http.MethodGet, originURL+"/x", "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d after snapshot swap", resp.StatusCode)
	}
}

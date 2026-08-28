package app

import (
	"context"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

const emptySpecYAML = "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec: {}\n"

var frozenFeatureIDs = []string{
	FeatureIDHTTP2,
	FeatureIDWebSocket,
	FeatureIDConnect,
	FeatureIDAbsoluteForm,
	FeatureIDAcceptSOCKS5,
	FeatureIDAcceptSOCKS4,
	FeatureIDOriginalDest,
	FeatureIDCompatFlowREST,
	FeatureIDTLSIntercept,
	FeatureIDRulesEnabled,
	FeatureIDUIEnabled,
}

var frozenFeatureVerbs = map[string]string{
	FeatureIDHTTP2:          FeatureVerbSetFeature,
	FeatureIDWebSocket:      FeatureVerbSetFeature,
	FeatureIDConnect:        FeatureVerbSetFeature,
	FeatureIDAbsoluteForm:   FeatureVerbSetFeature,
	FeatureIDAcceptSOCKS5:   FeatureVerbSetFeature,
	FeatureIDAcceptSOCKS4:   FeatureVerbSetFeature,
	FeatureIDOriginalDest:   FeatureVerbReset,
	FeatureIDCompatFlowREST: FeatureVerbSetFeature,
	FeatureIDTLSIntercept:   FeatureVerbReplaceTLS,
	FeatureIDRulesEnabled:   FeatureVerbSetFeature,
	FeatureIDUIEnabled:      FeatureVerbSetFeature,
}

var frozenFeatureYAMLPaths = map[string]string{
	FeatureIDHTTP2:          "spec.protocols.http2.enabled",
	FeatureIDWebSocket:      "spec.protocols.websocket.enabled",
	FeatureIDConnect:        "spec.protocols.connect.enabled",
	FeatureIDAbsoluteForm:   "spec.protocols.absoluteForm.enabled",
	FeatureIDAcceptSOCKS5:   "spec.listeners.proxy.acceptSOCKS5",
	FeatureIDAcceptSOCKS4:   "spec.listeners.proxy.acceptSOCKS4",
	FeatureIDOriginalDest:   "spec.listeners.originalDestination.enabled",
	FeatureIDCompatFlowREST: "spec.compat.flowREST.enabled",
	FeatureIDTLSIntercept:   "spec.tls.intercept",
	FeatureIDRulesEnabled:   "spec.rules.enabled",
	FeatureIDUIEnabled:      "spec.ui.enabled",
}

func TestCatalogFromSpecEmptyLoadDefaultsOn(t *testing.T) {
	st, err := config.Load([]byte(emptySpecYAML))
	if err != nil {
		t.Fatal(err)
	}
	items := CatalogFromSpec(st.Spec)
	if len(items) != len(frozenFeatureIDs) {
		t.Fatalf("len=%d want %d", len(items), len(frozenFeatureIDs))
	}
	for i, id := range frozenFeatureIDs {
		if items[i].ID != id {
			t.Fatalf("items[%d].ID=%q want %q", i, items[i].ID, id)
		}
		if items[i].Verb != frozenFeatureVerbs[id] {
			t.Fatalf("%s verb=%q want %q", id, items[i].Verb, frozenFeatureVerbs[id])
		}
		wantMode := FeatureApplyLive
		if id == FeatureIDOriginalDest {
			wantMode = FeatureApplyReset
		}
		if items[i].ApplyMode != wantMode {
			t.Fatalf("%s applyMode=%q want %q", id, items[i].ApplyMode, wantMode)
		}
		if items[i].YAMLPath != frozenFeatureYAMLPaths[id] {
			t.Fatalf("%s yamlPath=%q want %q", id, items[i].YAMLPath, frozenFeatureYAMLPaths[id])
		}
		if items[i].Title == "" || items[i].Description == "" {
			t.Fatalf("%s missing title/description", id)
		}
		if id == FeatureIDWebSocket || id == FeatureIDConnect || id == FeatureIDAbsoluteForm {
			if !strings.Contains(items[i].Description, "setFeature is validation_failed until hop 403 lands") {
				t.Fatalf("%s description missing staged-apply residual: %q", id, items[i].Description)
			}
		}
	}
	wantOn := map[string]bool{
		FeatureIDWebSocket:    true,
		FeatureIDConnect:      true,
		FeatureIDAbsoluteForm: true,
		FeatureIDUIEnabled:    true,
	}
	for _, f := range items {
		if f.Enabled != wantOn[f.ID] {
			t.Fatalf("%s enabled=%v want %v", f.ID, f.Enabled, wantOn[f.ID])
		}
	}
	flags := CompactStatusFlags(items)
	if flags.HTTP2 || flags.SOCKS5 || flags.SOCKS4 || flags.OriginalDestination || flags.CompatFlowREST {
		t.Fatalf("compact flags on empty spec: %+v", flags)
	}
}

func TestCatalogFromSpecZeroSpecDoesNotDefault(t *testing.T) {
	items := CatalogFromSpec(model.Spec{})
	for _, f := range items {
		if f.Enabled {
			t.Fatalf("zero Spec reported %s on; CatalogFromSpec must not default bools", f.ID)
		}
	}
}

func TestCatalogFromSpecWebSocketEnabledNotInspectFrames(t *testing.T) {
	st, err := config.Load([]byte(emptySpecYAML))
	if err != nil {
		t.Fatal(err)
	}
	st.Spec.Protocols.WebSocket.Enabled = false
	st.Spec.Protocols.WebSocket.InspectFrames = true
	items := CatalogFromSpec(st.Spec)
	f, ok := featureByID(items, FeatureIDWebSocket)
	if !ok {
		t.Fatal("missing websocket")
	}
	if f.Enabled {
		t.Fatal("websocket catalog bit must follow Enabled, not InspectFrames")
	}
}

func TestCatalogFromSpecExplicitBits(t *testing.T) {
	st, err := config.Load([]byte(emptySpecYAML))
	if err != nil {
		t.Fatal(err)
	}
	st.Spec.Protocols.HTTP2.Enabled = true
	st.Spec.Listeners.Proxy.AcceptSOCKS5 = true
	st.Spec.Listeners.Proxy.AcceptSOCKS4 = true
	st.Spec.Listeners.OriginalDestination.Enabled = true
	st.Spec.Compat.FlowREST.Enabled = true
	st.Spec.TLS.Intercept = true
	st.Spec.Rules.Enabled = true
	st.Spec.UI.Enabled = false
	st.Spec.Protocols.Connect.Enabled = false
	st.Spec.Protocols.AbsoluteForm.Enabled = false
	items := CatalogFromSpec(st.Spec)
	want := map[string]bool{
		FeatureIDHTTP2:          true,
		FeatureIDWebSocket:      true,
		FeatureIDConnect:        false,
		FeatureIDAbsoluteForm:   false,
		FeatureIDAcceptSOCKS5:   true,
		FeatureIDAcceptSOCKS4:   true,
		FeatureIDOriginalDest:   true,
		FeatureIDCompatFlowREST: true,
		FeatureIDTLSIntercept:   true,
		FeatureIDRulesEnabled:   true,
		FeatureIDUIEnabled:      false,
	}
	for _, f := range items {
		if f.Enabled != want[f.ID] {
			t.Fatalf("%s enabled=%v want %v", f.ID, f.Enabled, want[f.ID])
		}
	}
	flags := CompactStatusFlags(items)
	if !flags.HTTP2 || !flags.SOCKS5 || !flags.SOCKS4 || !flags.OriginalDestination || !flags.CompatFlowREST {
		t.Fatalf("compact flags=%+v", flags)
	}
}

func TestAppFeaturesMatchesSnapshotAndLeavesInbox(t *testing.T) {
	svc, snap := mustBoot(t)
	id := insertRaw(t, svc, "catalog.lab")
	list, err := svc.Features(context.Background(), actor())
	if err != nil {
		t.Fatal(err)
	}
	if list.RuntimeRevision != snap.Revision || list.Generation != snap.Generation || list.Drifted {
		t.Fatalf("meta revision=%s gen=%d drifted=%v", list.RuntimeRevision, list.Generation, list.Drifted)
	}
	if len(list.Items) != len(frozenFeatureIDs) {
		t.Fatalf("len=%d", len(list.Items))
	}
	ws, ok := featureByID(list.Items, FeatureIDWebSocket)
	if !ok || !ws.Enabled {
		t.Fatal("booted defaults must report websocket on")
	}
	st, err := svc.Status(context.Background(), actor())
	if err != nil {
		t.Fatal(err)
	}
	flags := CompactStatusFlags(list.Items)
	if st.Features != flags {
		t.Fatalf("Status.Features=%+v catalog compact=%+v", st.Features, flags)
	}
	if svc.Inbox().Stats().FlowCount != 1 {
		t.Fatal("Features must not wipe the flow store")
	}
	if _, err := svc.GetFlow(context.Background(), actor(), id); err != nil {
		t.Fatal(err)
	}
}

func TestFeatureCatalogDoesNotGrowCapabilityTable(t *testing.T) {
	if capabilities.TableRowCount != 30 {
		t.Fatalf("TableRowCount=%d; features.get is not in this change", capabilities.TableRowCount)
	}
}

func TestFeaturesNoSnapshot(t *testing.T) {
	svc := New(Options{})
	_, err := svc.Features(context.Background(), actor())
	requireCode(t, err, domainerr.CodeInternalError)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = svc.Features(ctx, actor())
	if err != context.Canceled {
		t.Fatalf("canceled ctx err=%v", err)
	}
}

func featureByID(items []Feature, id string) (Feature, bool) {
	for _, f := range items {
		if f.ID == id {
			return f, true
		}
	}
	return Feature{}, false
}

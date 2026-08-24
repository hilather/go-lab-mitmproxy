package observability

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogLabelPolicy(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Metrics() {
		if m.Name == "" || m.Kind == "" || m.Help == "" {
			t.Fatalf("incomplete metric %+v", m)
		}
		if seen[m.Name] {
			t.Fatalf("duplicate metric %s", m.Name)
		}
		seen[m.Name] = true
		if !strings.HasPrefix(m.Name, "labmitm_") {
			t.Fatalf("metric %s missing labmitm_ prefix", m.Name)
		}
		for _, l := range m.Labels {
			if ForbiddenLabel(l) {
				t.Fatalf("%s declares forbidden label %q", m.Name, l)
			}
			if !AllowedLabel(l) {
				t.Fatalf("%s declares undeclared label %q", m.Name, l)
			}
		}
		lower := strings.ToLower(m.Name + " " + strings.Join(m.Labels, " "))
		if strings.Contains(lower, "subject") || strings.Contains(lower, "client_ip") ||
			strings.Contains(lower, "address") {
			t.Fatalf("catalog row mentions subject/address/client_ip: %s", m.Name)
		}
	}
	required := []string{
		MetricProxySessionsTotal, MetricProxyRejectedTotal, MetricSocksSessionsTotal, MetricFlowsTotal,
		MetricTLSInterceptsTotal, MetricRuleHitsTotal, MetricStoreFlows,
		MetricStoreBytes, MetricStoreEvictions, MetricStoreFullTotal,
		MetricStoreWaiters, MetricHTTPRequestsTotal, MetricHTTPRequestDuration,
		MetricMCPCallsTotal, MetricAuthFailuresTotal, MetricAuditEventsTotal,
		MetricH2TrailerDroppedTotal, MetricWSFramesTotal, MetricGRPCDecodeTotal,
		MetricH2PushCapturedTotal,
	}
	for _, name := range required {
		if !seen[name] {
			t.Fatalf("missing frozen metric %s", name)
		}
	}
}

func TestCatalogMatchesGeneratedArtifact(t *testing.T) {
	got, err := RenderCatalog()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repoRoot(t), CatalogRelPath)
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run make generate)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; run make generate", CatalogRelPath)
	}
	var doc Document
	if err := json.Unmarshal(want, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ID != CatalogID {
		t.Fatalf("id=%s", doc.ID)
	}
	if len(doc.Metrics) != len(Metrics()) || len(doc.Events) != len(Events()) {
		t.Fatalf("artifact metrics=%d events=%d", len(doc.Metrics), len(doc.Events))
	}
}

func TestEventsHaveStableFields(t *testing.T) {
	want := []string{
		EventProxyAccepted, EventProxyRejected, EventProxySessionEnd,
		EventTLSIntercept, EventTLSUpstreamInsec,
		EventStoreInserted, EventStoreDeleted, EventStoreWiped, EventStoreFull,
		EventRuleHit, EventFlowPaused, EventFlowResumed,
		EventHTTPRequest, EventMCPCall, EventAuthFailure, EventAuthSuccess,
		EventStateReset, EventStateApply,
	}
	got := map[string]bool{}
	for _, e := range Events() {
		if e.Name == "" {
			t.Fatal("empty event name")
		}
		got[e.Name] = true
		joined := strings.Join(e.Fields, ",")
		if !strings.Contains(joined, "event") || !strings.Contains(joined, "request_id") ||
			!strings.Contains(joined, "flow_id") || !strings.Contains(joined, "host_class") ||
			!strings.Contains(joined, "store_generation") {
			t.Fatalf("event %s missing required fields: %v", e.Name, e.Fields)
		}
	}
	for _, n := range want {
		if !got[n] {
			t.Fatalf("missing frozen event %s", n)
		}
	}
}

func TestForbiddenAndAllowed(t *testing.T) {
	for _, k := range []string{"subject", "SUBJECT", "client_ip", "actor_id", "from", "to", "password", "authorization", "host", "cookie"} {
		if !ForbiddenLabel(k) {
			t.Fatalf("%s should be forbidden", k)
		}
	}
	for _, k := range []string{"result", "capability", "code_class", "tool", "reason", "event", "action", "scheme", "intercepted", "opcode"} {
		if !AllowedLabel(k) {
			t.Fatalf("%s should be allowed", k)
		}
		if ForbiddenLabel(k) {
			t.Fatalf("%s must not also be forbidden", k)
		}
	}
}

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

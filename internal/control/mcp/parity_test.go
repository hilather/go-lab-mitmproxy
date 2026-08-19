package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
)

func TestParityEveryRequiredRowHasMCPTool(t *testing.T) {
	s, _ := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	live := map[string]bool{}
	for tool, err := range cs.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		live[tool.Name] = true
	}
	for _, c := range capabilities.All() {
		if c.RESTOnly || c.DifferentBinding {
			continue
		}
		if c.MCP == nil || len(c.MCP.Tools) == 0 {
			t.Errorf("%s missing MCP tool", c.ID)
			continue
		}
		for _, name := range c.MCP.Tools {
			if !live[name] {
				t.Errorf("%s tool %s not registered on the live server", c.ID, name)
			}
		}
	}
}

func TestParityGoldens(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "testdata", "mcp", "goldens")
	compareLines(t, filepath.Join(dir, "tools.txt"), capabilities.Tools())
	compareLines(t, filepath.Join(dir, "resources.txt"), capabilities.Resources())
	compareLines(t, filepath.Join(dir, "mutating-tools.txt"), mutatingTools())
}

func TestParityMCPMutationsHaveREST(t *testing.T) {
	for _, c := range capabilities.All() {
		if !c.Mutating {
			continue
		}
		if c.RESTOnly {
			continue
		}
		if len(c.REST) == 0 {
			t.Errorf("%s mutating without REST", c.ID)
		}
		if c.MCP == nil || len(c.MCP.Tools) == 0 {
			t.Errorf("%s mutating without MCP tool", c.ID)
		}
	}
}

func TestParityStructuredErrorsMatch(t *testing.T) {
	s, _ := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	err := callToolExpectError(t, cs, "mitm_flow_get", map[string]any{"id": "01AAAAAAAAAAAAAAAAAAAAAAAA"})
	if domainCode(t, err) != "not_found" {
		t.Fatalf("want not_found, got %v", err)
	}
}

func mutatingTools() []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range capabilities.All() {
		if c.MCP == nil || !c.Mutating {
			continue
		}
		for _, name := range c.MCP.Tools {
			if seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

func compareLines(t *testing.T, path string, got []string) {
	t.Helper()
	wantBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (create the golden)", path, err)
	}
	want := strings.Split(strings.TrimSpace(string(wantBytes)), "\n")
	if len(want) == 1 && want[0] == "" {
		want = nil
	}
	if !stringSlicesEqual(want, got) {
		t.Errorf("%s mismatch\nwant:\n%s\ngot:\n%s", path, strings.Join(want, "\n"), strings.Join(got, "\n"))
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestManifestGolden(t *testing.T) {
	want, err := RenderManifest()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repoRoot(t), filepath.FromSlash(ManifestRelPath))
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run make generate)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; run make generate", ManifestRelPath)
	}
	var doc Manifest
	if err := json.Unmarshal(want, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Protocol != ProtocolVersion {
		t.Fatalf("manifest protocol=%q", doc.Protocol)
	}
	if len(doc.Tools) == 0 || len(doc.Resources) == 0 {
		t.Fatalf("manifest incomplete: %+v", doc)
	}
}

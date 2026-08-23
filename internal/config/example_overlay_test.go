package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// TestLabOverlayExample loads examples/labmitm.yaml (the mcp-integration-lab
// bootstrap) and checks the overlay knobs the lab PR must not regress.
func TestLabOverlayExample(t *testing.T) {
	path := filepath.Join(repoRoot(t), "examples", "labmitm.yaml")
	st, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Spec.Management.MCP.AllowLegacyClients {
		t.Fatal("lab overlay must set allowLegacyClients: true (D15)")
	}
	if st.Spec.Management.Auth.Mode != model.MgmtAuthBearer {
		t.Fatalf("auth.mode=%q want bearer (D6; no HTTP Basic)", st.Spec.Management.Auth.Mode)
	}
	if st.Spec.Listeners.Proxy.Address != ":8888" || st.Spec.Listeners.Management.Address != ":8088" {
		t.Fatalf("listeners proxy=%q mgmt=%q", st.Spec.Listeners.Proxy.Address, st.Spec.Listeners.Management.Address)
	}
	if !st.Spec.UI.Enabled {
		t.Fatal("ui.enabled must stay true (D13: flow-inspector UI required for GA)")
	}
	if !st.Spec.TLS.Intercept {
		t.Fatal("lab overlay enables tls.intercept (profile may turn it off)")
	}
	found := false
	for _, tok := range st.Spec.Management.Auth.Tokens {
		if tok.ID == "admin" && tok.SecretFile == "/run/secrets/labmitm-token" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("missing admin token at /run/secrets/labmitm-token")
	}
	wantHosts := []string{"*.lab", "labdns", "labinfo", "maildev", "mcpjungle", "control", "taclab"}
	if !slices.Equal(st.Spec.Proxy.Targets.AllowHosts, wantHosts) {
		t.Fatalf("allowHosts=%v want %v", st.Spec.Proxy.Targets.AllowHosts, wantHosts)
	}
	for _, o := range st.Spec.Management.OriginAllowlist {
		if o == "*" || o == "private" {
			t.Fatalf("originAllowlist must not contain %q", o)
		}
	}
	if st.Spec.Protocols.HTTP2.Enabled {
		t.Fatal("protocols.http2.enabled must stay false")
	}
	if st.Spec.Listeners.Proxy.AcceptSOCKS5 || st.Spec.Listeners.Proxy.AcceptSOCKS4 {
		t.Fatal("acceptSOCKS5/acceptSOCKS4 must stay false")
	}
	if st.Spec.Listeners.OriginalDestination.Enabled {
		t.Fatal("originalDestination.enabled must stay false")
	}
	if st.Spec.Compat.FlowREST.Enabled {
		t.Fatal("compat.flowREST.enabled must stay false")
	}
}

func TestLabMCPJungleExamples(t *testing.T) {
	root := filepath.Join(repoRoot(t), "examples", "mcpjungle")
	raw, err := os.ReadFile(filepath.Join(root, "servers", "labmitm.json"))
	if err != nil {
		t.Fatal(err)
	}
	var server struct {
		Name        string `json:"name"`
		Transport   string `json:"transport"`
		URL         string `json:"url"`
		BearerToken string `json:"bearer_token"`
	}
	if err := json.Unmarshal(raw, &server); err != nil {
		t.Fatal(err)
	}
	if server.Name != "labmitm" {
		t.Fatalf("name=%q (filename must match name; lab AGENTS.md rule 8)", server.Name)
	}
	if server.Transport != "streamable_http" {
		t.Fatalf("transport=%q", server.Transport)
	}
	if server.URL != "http://labmitm:8088/mcp" {
		t.Fatalf("url=%q", server.URL)
	}
	if server.BearerToken != "${LABMITM_TOKEN}" {
		t.Fatalf("bearer_token=%q", server.BearerToken)
	}

	grow, err := os.ReadFile(filepath.Join(root, "groups", "integration.json"))
	if err != nil {
		t.Fatal(err)
	}
	var group struct {
		Name            string   `json:"name"`
		IncludedServers []string `json:"included_servers"`
	}
	if err := json.Unmarshal(grow, &group); err != nil {
		t.Fatal(err)
	}
	if group.Name != "integration" {
		t.Fatalf("group name=%q", group.Name)
	}
	want := []string{"labdns", "labldap", "labtacacs", "labinfo", "labmail", "labmitm"}
	if !slices.Equal(group.IncludedServers, want) {
		t.Fatalf("included_servers=%v want %v (append labmitm; do not replace)", group.IncludedServers, want)
	}
}

func TestLabinfoSnippetKeepsCatalogID(t *testing.T) {
	path := filepath.Join(repoRoot(t), "examples", "labinfo", "services-labmitm.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "id: labmitm") {
		t.Fatal("D18: catalog id must be labmitm")
	}
	if strings.Contains(text, "id: mitmproxy") {
		t.Fatal("do not invent a legacy mitmproxy catalog id")
	}
	if !strings.Contains(text, "/v1") || !strings.Contains(text, "/mcp") {
		t.Fatal("snippet must add native /v1 and MCP URLs")
	}
	if !strings.Contains(text, "labmitm-token") {
		t.Fatal("snippet must add bearer credential file")
	}
	if strings.Contains(text, "follow-on") {
		t.Fatal("snippet must not say compose-in is a follow-on")
	}
	if !strings.Contains(text, "v1.1.0") || !strings.Contains(text, "labmitm:local") {
		t.Fatal("snippet must name the lab pin (vendor v1.1.0 + labmitm:local)")
	}
	if strings.Contains(text, "ghcr.io") {
		t.Fatal("snippet must not claim a fictional GHCR digest")
	}
}

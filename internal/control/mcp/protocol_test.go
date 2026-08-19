package mcp

import (
	"net/http"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/buildinfo"
)

func TestProtocolVersionRequired(t *testing.T) {
	s, _ := newTestServer(t)
	req := doRaw(t, s.Handler(), rpcCall(1, "server/discover", nil), map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json, text/event-stream",
	}, "127.0.0.1:1")
	requireRPCError(t, req, http.StatusBadRequest, "validation_failed")
}

func TestProtocolVersionMismatch(t *testing.T) {
	s, _ := newTestServer(t)
	rec := doRaw(t, s.Handler(), rpcCall(1, "server/discover", nil), map[string]string{
		"Content-Type":        "application/json",
		"Accept":              "application/json, text/event-stream",
		headerProtocolVersion: "2025-11-25",
	}, "127.0.0.1:1")
	requireRPCError(t, rec, http.StatusBadRequest, "validation_failed")
}

func TestPinnedProtocolDiscover(t *testing.T) {
	s, _ := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	ir := cs.InitializeResult()
	if ir == nil {
		t.Fatal("missing initialize/discover result")
	}
	if ir.ProtocolVersion != ProtocolVersion {
		t.Fatalf("negotiated %q want %s", ir.ProtocolVersion, ProtocolVersion)
	}
	if buildinfo.Current().Protocols.MCP != ProtocolVersion {
		t.Fatalf("buildinfo MCP=%q", buildinfo.Current().Protocols.MCP)
	}
}

func TestDiscoverAdvertisesOnlyPinnedVersion(t *testing.T) {
	s, _ := newTestServer(t)
	body := rpcCall(1, "server/discover", map[string]any{
		"_meta": map[string]any{
			"io.modelcontextprotocol/protocolVersion": ProtocolVersion,
			"io.modelcontextprotocol/clientInfo": map[string]any{
				"name": "labmitm-test", "version": "dev",
			},
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		},
	})
	rec := doRaw(t, s.Handler(), body, map[string]string{
		"Content-Type":        "application/json",
		"Accept":              "application/json, text/event-stream",
		headerProtocolVersion: ProtocolVersion,
		"Mcp-Method":          "server/discover",
	}, "127.0.0.1:1")
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Fatalf("discover status=%d body=%s", rec.Code, rec.Body.String())
	}
	m := decodeRPC(t, rec)
	result, _ := m["result"].(map[string]any)
	if result == nil {
		t.Fatalf("discover missing result: %s", rec.Body.String())
	}
	raw, _ := result["supportedVersions"].([]any)
	if len(raw) != 1 || raw[0] != ProtocolVersion {
		t.Fatalf("supportedVersions=%v want [%s]", raw, ProtocolVersion)
	}
}

func TestStreamableHTTPOnlyPOST(t *testing.T) {
	s, _ := newTestServer(t)
	req := doRawMethod(t, s.Handler(), http.MethodGet, DefaultPath, "", map[string]string{
		"Accept":              "text/event-stream",
		headerProtocolVersion: ProtocolVersion,
	}, "127.0.0.1:1")
	if req.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status=%d want 405 body=%s", req.Code, req.Body.String())
	}
}

func TestClosedRejectsRequests(t *testing.T) {
	s, _ := newTestServer(t)
	s.Close()
	rec := doRaw(t, s.Handler(), rpcCall(1, "ping", nil), map[string]string{
		"Content-Type":        "application/json",
		"Accept":              "application/json, text/event-stream",
		headerProtocolVersion: ProtocolVersion,
	}, "127.0.0.1:1")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestStatelessNoSessionHeader(t *testing.T) {
	s, _ := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	_ = callTool(t, cs, "mitm_version_get", map[string]any{})
	_ = callTool(t, cs, "mitm_version_get", map[string]any{})
}

func TestAllowLegacyClientsNegotiatesViaSDK(t *testing.T) {
	_, svc := newTestServer(t)
	s, err := New(Config{Service: svc, RatePerSec: -1, AllowLegacyClients: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"legacy-gateway","version":"0.0.1"}}}`
	rec := doRaw(t, s.Handler(), body, map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json, text/event-stream",
	}, "127.0.0.1:1")
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Fatalf("legacy initialize status=%d body=%s", rec.Code, rec.Body.String())
	}
	got := decodeRPC(t, rec)
	result, _ := got["result"].(map[string]any)
	if result == nil || result["protocolVersion"] == "" {
		t.Fatalf("legacy initialize missing result.protocolVersion: %s", rec.Body.String())
	}
	rec2 := doRaw(t, s.Handler(), body, map[string]string{
		"Content-Type":        "application/json",
		"Accept":              "application/json, text/event-stream",
		headerProtocolVersion: "2025-03-26",
	}, "127.0.0.1:1")
	if rec2.Code == http.StatusBadRequest {
		t.Fatalf("legacy mismatched header rejected: %s", rec2.Body.String())
	}
}

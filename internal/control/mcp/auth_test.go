package mcp

import (
	"encoding/base64"
	"net/http"
	"testing"
)

func TestBasicRejected(t *testing.T) {
	s, _ := newTestServer(t)
	rec := doRaw(t, s.Handler(), rpcCall(1, "ping", nil), map[string]string{
		"Content-Type":        "application/json",
		"Accept":              "application/json, text/event-stream",
		headerProtocolVersion: ProtocolVersion,
		headerAuthorization:   "Basic YWRtaW46c2VjcmV0",
	}, "127.0.0.1:1")
	requireRPCError(t, rec, http.StatusUnauthorized, "unauthenticated")
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate")
	}
}

func TestBearerStubAccepted(t *testing.T) {
	s, _ := newTestServer(t)
	rec := doRaw(t, s.Handler(), rpcCall(1, "ping", nil), map[string]string{
		"Content-Type":        "application/json",
		"Accept":              "application/json, text/event-stream",
		headerProtocolVersion: ProtocolVersion,
		headerAuthorization:   "Bearer stub-token",
	}, "127.0.0.1:1")
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("bearer rejected: %s", rec.Body.String())
	}
}

func TestMCPAuthVerifierBearerOnly(t *testing.T) {
	s, _ := newTestServer(t)
	v, token := testVerifier(t)
	s.cfg.Auth = v
	hdr := map[string]string{
		"Content-Type":        "application/json",
		"Accept":              "application/json, text/event-stream",
		headerProtocolVersion: ProtocolVersion,
	}
	hdr[headerAuthorization] = "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:lab-web-pass"))
	rec := doRaw(t, s.Handler(), rpcCall(1, "ping", nil), hdr, "127.0.0.1:1")
	requireRPCError(t, rec, http.StatusUnauthorized, "unauthenticated")

	hdr[headerAuthorization] = "Bearer " + token
	rec = doRaw(t, s.Handler(), rpcCall(1, "tools/call", map[string]any{
		"name": "mitm_flows_list", "arguments": map[string]any{"limit": 1},
	}), hdr, "127.0.0.1:1")
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("valid bearer tool rejected: %s", rec.Body.String())
	}

	delete(hdr, headerAuthorization)
	rec = doRaw(t, s.Handler(), rpcCall(1, "ping", nil), hdr, "127.0.0.1:1")
	requireRPCError(t, rec, http.StatusUnauthorized, "unauthenticated")
}

func TestMCPScopedToolsUnderVerifier(t *testing.T) {
	s, _ := newTestServer(t)
	v, adminTok, viewTok := testVerifierWithViewer(t)
	s.cfg.Auth = v
	ts := startHTTP(t, s)

	admin := connectClientAuth(t, ts, adminTok)
	if res := callTool(t, admin, "mitm_flows_list", map[string]any{"limit": 1}); res.IsError {
		t.Fatalf("admin list: %+v", res)
	}

	viewer := connectClientAuth(t, ts, viewTok)
	if res := callTool(t, viewer, "mitm_flows_list", map[string]any{"limit": 1}); res.IsError {
		t.Fatalf("viewer list: %+v", res)
	}
	denied := callTool(t, viewer, "mitm_state_reset", map[string]any{})
	if !denied.IsError {
		t.Fatal("viewer reset must be forbidden")
	}
}

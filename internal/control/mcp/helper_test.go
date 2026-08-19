package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/auth"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const testBearerToken = "0123456789abcdef0123456789abcdef"

func testVerifier(t *testing.T) (*auth.Verifier, string) {
	t.Helper()
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte(testBearerToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := auth.FromSpec(model.MgmtAuthSpec{
		Mode: model.MgmtAuthBearer,
		Tokens: []model.TokenSpec{{
			ID: "admin", SecretFile: tok, Role: model.RoleAdministrator,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return v, testBearerToken
}

const testViewerToken = "fedcba9876543210fedcba9876543210"

func testVerifierWithViewer(t *testing.T) (*auth.Verifier, string, string) {
	t.Helper()
	dir := t.TempDir()
	adminPath := filepath.Join(dir, "admin")
	if err := os.WriteFile(adminPath, []byte(testBearerToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	viewPath := filepath.Join(dir, "viewer")
	if err := os.WriteFile(viewPath, []byte(testViewerToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := auth.FromSpec(model.MgmtAuthSpec{
		Mode: model.MgmtAuthBearer,
		Tokens: []model.TokenSpec{
			{ID: "admin", SecretFile: adminPath, Role: model.RoleAdministrator},
			{ID: "viewer", SecretFile: viewPath, Role: model.RoleViewer, Scopes: []string{model.ScopeMITMRead}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return v, testBearerToken, testViewerToken
}

type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (b bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set(headerAuthorization, "Bearer "+b.token)
	base := b.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}

func connectClientAuth(t *testing.T, ts *httptest.Server, token string) *sdk.ClientSession {
	t.Helper()
	client := sdk.NewClient(&sdk.Implementation{Name: "labmitm-test", Version: "dev"}, nil)
	session, err := client.Connect(t.Context(), &sdk.StreamableClientTransport{
		Endpoint:             ts.URL + DefaultPath,
		DisableStandaloneSSE: true,
		HTTPClient:           &http.Client{Transport: bearerRoundTripper{token: token}},
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
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

func newTestServer(t *testing.T) (*Server, *app.App) {
	t.Helper()
	svc, err := app.Boot(context.Background(), app.Options{BootstrapPath: copyDefaults(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	svc.SetReplay(func(_ context.Context, stored *model.Flow) (*model.Flow, error) {
		out := *stored
		out.ID = "01REPLAYFLOW00000000000000"
		out.Status = 200
		return &out, nil
	})
	s, err := New(Config{Service: svc, RatePerSec: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, svc
}

func insertFlow(t *testing.T, svc *app.App, host string) string {
	t.Helper()
	res, err := svc.Inbox().Insert(context.Background(), svc.Inbox().Epoch(), &model.Flow{
		Host:     host,
		Method:   "GET",
		URL:      "http://" + host + "/",
		Scheme:   "http",
		Protocol: model.FlowProtocolHTTP11,
		State:    model.FlowStateCompleted,
		Status:   200,
		Request:  model.HTTPMessage{Body: []byte("req"), Size: 3},
		Response: model.HTTPMessage{Body: []byte("resp"), Size: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.ID
}

func rpcCall(id int, method string, params any) string {
	p := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		p["params"] = params
	} else {
		p["params"] = map[string]any{
			"_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": ProtocolVersion},
		}
	}
	b, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func doRaw(t *testing.T, h http.Handler, body string, hdr map[string]string, remote string) *httptest.ResponseRecorder {
	t.Helper()
	return doRawMethod(t, h, http.MethodPost, DefaultPath, body, hdr, remote)
}

func doRawMethod(t *testing.T, h http.Handler, method, path, body string, hdr map[string]string, remote string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remote
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeRPC(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	raw := rec.Body.Bytes()
	if bytes.Contains(raw, []byte("event:")) {
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "data:") {
				raw = []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("json: %v body=%s", err, rec.Body.String())
	}
	return out
}

func requireRPCError(t *testing.T, rec *httptest.ResponseRecorder, status int, domainCode string) map[string]any {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status=%d want %d body=%s", rec.Code, status, rec.Body.String())
	}
	m := decodeRPC(t, rec)
	errObj, _ := m["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("missing error: %s", rec.Body.String())
	}
	data, _ := errObj["data"].(map[string]any)
	if data == nil {
		t.Fatalf("missing error.data: %s", rec.Body.String())
	}
	if got, _ := data["code"].(string); got != domainCode {
		t.Fatalf("data.code=%v want %s body=%s", data["code"], domainCode, rec.Body.String())
	}
	return errObj
}

func startHTTP(t *testing.T, s *Server) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func connectClient(t *testing.T, ts *httptest.Server) *sdk.ClientSession {
	t.Helper()
	client := sdk.NewClient(&sdk.Implementation{Name: "labmitm-test", Version: "dev"}, nil)
	session, err := client.Connect(t.Context(), &sdk.StreamableClientTransport{
		Endpoint:             ts.URL + DefaultPath,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func callTool(t *testing.T, cs *sdk.ClientSession, name string, args any) *sdk.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	return res
}

func structuredMap(t *testing.T, res *sdk.CallToolResult) map[string]any {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("structured: %v raw=%s", err, raw)
	}
	return out
}

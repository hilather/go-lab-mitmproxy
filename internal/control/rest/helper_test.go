package rest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/auth"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

const testToken = "0123456789abcdef0123456789abcdef"

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

func bootTestApp(t *testing.T) *app.App {
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
	return svc
}

func newTestServer(t *testing.T) (*Server, *app.App) {
	t.Helper()
	svc := bootTestApp(t)
	s, err := New(Config{
		Service:    svc,
		RatePerSec: -1,
		Auth:       auth.Static(testToken, "admin", model.RoleAdministrator),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, svc
}

func doReq(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doReqAuth(t, h, method, path, body, testToken)
}

func doReqAuth(t *testing.T, h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = "127.0.0.1:54321"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func httptestReq(method, path, body string) *http.Request {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = "127.0.0.1:54321"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	return req
}

func doRaw(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("json: %v body=%s", err, rec.Body.String())
	}
	return out
}

func requireStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status=%d want %d body=%s", rec.Code, want, rec.Body.String())
	}
}

func requireProblem(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) map[string]any {
	t.Helper()
	requireStatus(t, rec, status)
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/problem+json") {
		t.Fatalf("content-type=%q", ct)
	}
	m := decodeJSON(t, rec)
	if got, _ := m["code"].(string); got != code {
		t.Fatalf("code=%v want %s body=%s", m["code"], code, rec.Body.String())
	}
	return m
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

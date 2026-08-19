package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/auth"
	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/web"
)

func TestCompatRoutesNotOnNativeCompile(t *testing.T) {
	s, _ := newTestServer(t)
	if len(s.compatRoutes) == 0 {
		t.Fatal("compatRoutes empty")
	}
	for _, rt := range s.routes {
		if strings.Contains(rt.path, "/compat") {
			t.Errorf("native compileRoutes saw %s %s", rt.method, rt.path)
		}
	}
	seen := map[string]bool{}
	for _, rt := range s.compatRoutes {
		seen[rt.method+" "+rt.path] = true
		if !strings.HasPrefix(rt.path, capabilities.DefaultCompatPathPrefix+"/") {
			t.Errorf("compat route %s not under %s", rt.path, capabilities.DefaultCompatPathPrefix)
		}
	}
	for _, c := range capabilities.CompatBindings() {
		for _, b := range c.REST {
			ref := strings.ToUpper(b.Method) + " " + b.Path
			if !seen[ref] {
				t.Errorf("missing compat route %s", ref)
			}
		}
	}
}

func TestCompatDisabled404NotSPA(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.UI = web.NewHandler(nil)
	s.cfg.UIEnabled = func() bool { return true }

	got := doReq(t, s.Handler(), http.MethodGet, "/compat/flows", "")
	requireProblem(t, got, http.StatusNotFound, "not_found")
	if strings.Contains(got.Body.String(), "<!doctype") || strings.Contains(got.Body.String(), "<html") {
		t.Fatal("disabled /compat/flows served SPA")
	}

	unknown := doReq(t, s.Handler(), http.MethodGet, "/compat/unknown", "")
	requireProblem(t, unknown, http.StatusNotFound, "not_found")
	if strings.Contains(unknown.Body.String(), "<!doctype") {
		t.Fatal("disabled /compat/unknown served SPA")
	}

	spa := doReqAuth(t, s.Handler(), http.MethodGet, "/flows", "", "")
	requireStatus(t, spa, http.StatusOK)
	if !strings.Contains(spa.Body.String(), "LabMITM") {
		t.Fatalf("SPA /flows body=%s", spa.Body.String())
	}
}

func TestCompatBasic401Bearer(t *testing.T) {
	s, _ := newCompatServer(t, "/compat")
	req := httptestReq(http.MethodGet, "/compat/flows", "")
	req.Header.Set("Authorization", "Basic YWRtaW46eA==")
	got := doRaw(s.Handler(), req)
	requireProblem(t, got, http.StatusUnauthorized, "unauthenticated")
	if got.Header().Get("WWW-Authenticate") != `Bearer realm="labmitm"` {
		t.Fatalf("www-authenticate=%q", got.Header().Get("WWW-Authenticate"))
	}
}

func TestCompatUnauthenticated401(t *testing.T) {
	s, _ := newCompatServer(t, "/compat")
	got := doReqAuth(t, s.Handler(), http.MethodGet, "/compat/flows", "", "")
	requireProblem(t, got, http.StatusUnauthorized, "unauthenticated")
}

func TestCompatListGetDeleteReplayContent(t *testing.T) {
	s, svc := newCompatServer(t, "/compat")
	h := s.Handler()
	id := insertFlow(t, svc, "app.lab")

	list := doReq(t, h, http.MethodGet, "/compat/flows", "")
	requireStatus(t, list, http.StatusOK)
	if list.Header().Get(headerTruncated) != "" {
		t.Fatalf("truncated on small list: %q", list.Header().Get(headerTruncated))
	}
	var items []map[string]any
	if err := json.Unmarshal(list.Body.Bytes(), &items); err != nil {
		t.Fatalf("list is not a JSON array: %s", list.Body.String())
	}
	if len(items) != 1 || items[0]["id"] != id {
		t.Fatalf("list=%s", list.Body.String())
	}
	req, _ := items[0]["request"].(map[string]any)
	if req["host"] != "app.lab" {
		t.Fatalf("mapped host=%v", req["host"])
	}

	got := doReq(t, h, http.MethodGet, "/compat/flows/"+id, "")
	requireStatus(t, got, http.StatusOK)
	gm := decodeJSON(t, got)
	if gm["id"] != id || gm["type"] != "http" {
		t.Fatalf("get=%s", got.Body.String())
	}

	raw := doReq(t, h, http.MethodGet, "/compat/flows/"+id+"/content/request", "")
	requireStatus(t, raw, http.StatusOK)
	if raw.Body.String() != "req" {
		t.Fatalf("request body %q", raw.Body.String())
	}
	if !strings.Contains(raw.Header().Get("Content-Type"), "application/octet-stream") {
		t.Fatalf("content-type=%s", raw.Header().Get("Content-Type"))
	}
	if raw.Header().Get("Content-Security-Policy") != "default-src 'none'" {
		t.Fatalf("csp=%q", raw.Header().Get("Content-Security-Policy"))
	}

	resp := doReq(t, h, http.MethodGet, "/compat/flows/"+id+"/content/response", "")
	requireStatus(t, resp, http.StatusOK)
	if resp.Body.String() != "resp" {
		t.Fatalf("response body %q", resp.Body.String())
	}

	replay := doReq(t, h, http.MethodPost, "/compat/flows/"+id+"/replay", "")
	requireStatus(t, replay, http.StatusOK)
	rm := decodeJSON(t, replay)
	if rm["id"] == id || rm["id"] == "" {
		t.Fatalf("replay must return a new flow: %s", replay.Body.String())
	}

	del := doReq(t, h, http.MethodDelete, "/compat/flows/"+id, "")
	requireStatus(t, del, http.StatusNoContent)

	missing := doReq(t, h, http.MethodGet, "/compat/flows/"+id, "")
	requireProblem(t, missing, http.StatusNotFound, "not_found")

	clear := doReq(t, h, http.MethodDelete, "/compat/flows", "")
	requireStatus(t, clear, http.StatusNoContent)

	native := doReq(t, h, http.MethodGet, "/v1/flows", "")
	requireStatus(t, native, http.StatusOK)
	nm := decodeJSON(t, native)
	if _, ok := nm["items"]; !ok {
		t.Fatalf("native /v1/flows must stay a paginated object: %s", native.Body.String())
	}
}

func TestCompatListTruncatedHeader(t *testing.T) {
	s, svc := newCompatServer(t, "/compat")
	for i := 0; i < 201; i++ {
		insertFlow(t, svc, "many.lab")
	}
	got := doReq(t, s.Handler(), http.MethodGet, "/compat/flows", "")
	requireStatus(t, got, http.StatusOK)
	if got.Header().Get(headerTruncated) != "true" {
		t.Fatalf("X-LabMITM-Truncated=%q", got.Header().Get(headerTruncated))
	}
	var items []map[string]any
	if err := json.Unmarshal(got.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 200 {
		t.Fatalf("len=%d want 200", len(items))
	}
}

func TestCompatCSRFOnCookieMutations(t *testing.T) {
	s, svc := newCompatAuthServer(t, "/compat")
	h := s.Handler()
	id := insertFlow(t, svc, "csrf.lab")

	req := httptestReq(http.MethodPost, "/v1/session", "")
	rec := doRaw(h, req)
	requireStatus(t, rec, http.StatusOK)
	csrf := decodeJSON(t, rec)["csrf"].(string)
	cookie := sessionCookie(t, rec.Result())

	del := httptestReq(http.MethodDelete, "/compat/flows/"+id, "")
	del.Header.Del("Authorization")
	del.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	requireProblem(t, doRaw(h, del), http.StatusForbidden, "forbidden")

	del = httptestReq(http.MethodDelete, "/compat/flows/"+id, "")
	del.Header.Del("Authorization")
	del.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	del.Header.Set(auth.CSRFHeader, csrf)
	requireStatus(t, doRaw(h, del), http.StatusNoContent)

	id2 := insertFlow(t, svc, "csrf-replay.lab")
	replay := httptestReq(http.MethodPost, "/compat/flows/"+id2+"/replay", "")
	replay.Header.Del("Authorization")
	replay.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	requireProblem(t, doRaw(h, replay), http.StatusForbidden, "forbidden")

	replay = httptestReq(http.MethodPost, "/compat/flows/"+id2+"/replay", "")
	replay.Header.Del("Authorization")
	replay.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	replay.Header.Set(auth.CSRFHeader, csrf)
	requireStatus(t, doRaw(h, replay), http.StatusOK)
}

func TestCompatCustomPrefix(t *testing.T) {
	s, svc := newCompatServer(t, "/legacy")
	id := insertFlow(t, svc, "legacy.lab")

	def := doReq(t, s.Handler(), http.MethodGet, "/compat/flows", "")
	requireProblem(t, def, http.StatusNotFound, "not_found")

	got := doReq(t, s.Handler(), http.MethodGet, "/legacy/flows/"+id, "")
	requireStatus(t, got, http.StatusOK)
	if decodeJSON(t, got)["id"] != id {
		t.Fatalf("get=%s", got.Body.String())
	}
}

func newCompatServer(t *testing.T, prefix string) (*Server, *app.App) {
	t.Helper()
	svc := bootCompatApp(t, prefix)
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

func newCompatAuthServer(t *testing.T, prefix string) (*Server, *app.App) {
	t.Helper()
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "labmitm.yaml")
	body := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec:\n  management:\n    auth:\n      mode: bearer\n      tokens:\n        - id: admin\n          secretFile: " + tok + "\n          role: administrator\n  compat:\n    flowREST:\n      enabled: true\n      pathPrefix: " + prefix + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, err := app.Boot(t.Context(), app.Options{BootstrapPath: cfg})
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
	v, err := auth.FromSpec(svc.Active().Canonical.Spec.Management.Auth)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Service: svc, Auth: v, RatePerSec: -1})
	if err != nil {
		t.Fatal(err)
	}
	return s, svc
}

func bootCompatApp(t *testing.T, prefix string) *app.App {
	t.Helper()
	if prefix == "" {
		prefix = capabilities.DefaultCompatPathPrefix
	}
	path := filepath.Join(t.TempDir(), "labmitm.yaml")
	body := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: compat\nspec:\n  compat:\n    flowREST:\n      enabled: true\n      pathPrefix: " + prefix + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, err := app.Boot(t.Context(), app.Options{BootstrapPath: path})
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

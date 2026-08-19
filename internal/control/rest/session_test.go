package rest

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/auth"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func newAuthServer(t *testing.T) (*Server, *app.App, *auth.Verifier) {
	t.Helper()
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "labmitm.yaml")
	body := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec:\n  management:\n    auth:\n      mode: bearer\n      tokens:\n        - id: admin\n          secretFile: " + tok + "\n          role: administrator\n"
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, err := app.Boot(t.Context(), app.Options{BootstrapPath: cfg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	v, err := auth.FromSpec(svc.Active().Canonical.Spec.Management.Auth)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Service: svc, Auth: v, RatePerSec: -1})
	if err != nil {
		t.Fatal(err)
	}
	return s, svc, v
}

func TestUnauthenticatedFlows401(t *testing.T) {
	s, _, _ := newAuthServer(t)
	got := doReqAuth(t, s.Handler(), http.MethodGet, "/v1/flows", "", "")
	requireProblem(t, got, http.StatusUnauthorized, "unauthenticated")
	if got.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate")
	}
	if got.Header().Get("WWW-Authenticate") != `Bearer realm="labmitm"` {
		t.Fatalf("www-authenticate=%q", got.Header().Get("WWW-Authenticate"))
	}
}

func TestNoOAuthPRM(t *testing.T) {
	s, _, _ := newAuthServer(t)
	got := doReqAuth(t, s.Handler(), http.MethodGet, "/.well-known/oauth-protected-resource", "", "")
	requireProblem(t, got, http.StatusNotFound, "not_found")
}

func TestSessionCookieAndCSRF(t *testing.T) {
	s, svc, _ := newAuthServer(t)
	h := s.Handler()

	req := httptestReq(http.MethodPost, "/v1/session", "")
	rec := doRaw(h, req)
	requireStatus(t, rec, http.StatusOK)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("POST /v1/session cache=%q", rec.Header().Get("Cache-Control"))
	}
	m := decodeJSON(t, rec)
	csrf, _ := m["csrf"].(string)
	if len(csrf) < 64 || m["expiresAt"] == "" {
		t.Fatalf("session body=%s", rec.Body.String())
	}
	var cookie string
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			cookie = c.Value
			if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Secure {
				t.Fatalf("cookie flags %+v", c)
			}
		}
	}
	if cookie == "" {
		t.Fatal("missing labmitm_session")
	}

	get := httptestReq(http.MethodGet, "/v1/session", "")
	get.Header.Del("Authorization")
	get.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	grec := doRaw(h, get)
	requireStatus(t, grec, http.StatusOK)
	if grec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET /v1/session cache=%q", grec.Header().Get("Cache-Control"))
	}
	gm := decodeJSON(t, grec)
	if gm["id"] != "admin" || gm["role"] != model.RoleAdministrator {
		t.Fatalf("get session=%s", grec.Body.String())
	}
	if gm["csrf"] != csrf {
		t.Fatalf("GET /v1/session must return csrf for cookie recovery: %s", grec.Body.String())
	}

	insertFlow(t, svc, "sess.lab")
	del := httptestReq(http.MethodDelete, "/v1/flows", "")
	del.Header.Del("Authorization")
	del.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	drec := doRaw(h, del)
	requireProblem(t, drec, http.StatusForbidden, "forbidden")

	del = httptestReq(http.MethodDelete, "/v1/flows", "")
	del.Header.Del("Authorization")
	del.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	del.Header.Set(auth.CSRFHeader, csrf)
	drec = doRaw(h, del)
	requireStatus(t, drec, http.StatusOK)

	logout := httptestReq(http.MethodDelete, "/v1/session", "")
	logout.Header.Del("Authorization")
	logout.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	logout.Header.Set(auth.CSRFHeader, csrf)
	lrec := doRaw(h, logout)
	if lrec.Code != http.StatusNoContent {
		t.Fatalf("logout=%d %s", lrec.Code, lrec.Body.String())
	}

	again := httptestReq(http.MethodGet, "/v1/session", "")
	again.Header.Del("Authorization")
	again.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	arec := doRaw(h, again)
	requireProblem(t, arec, http.StatusUnauthorized, "unauthenticated")
}

func TestAuditRecordsAuthIdentity(t *testing.T) {
	s, svc, _ := newAuthServer(t)
	id := insertFlow(t, svc, "audit-me.lab")
	req := httptestReq(http.MethodDelete, "/v1/flows/"+id, "")
	rec := doRaw(s.Handler(), req)
	requireStatus(t, rec, http.StatusNoContent)

	list := httptestReq(http.MethodGet, "/v1/audit", "")
	got := doRaw(s.Handler(), list)
	requireStatus(t, got, http.StatusOK)
	if !strings.Contains(got.Body.String(), `"actorId":"admin"`) {
		t.Fatalf("audit missing actor: %s", got.Body.String())
	}
}

func TestHealthSkipsAuth(t *testing.T) {
	s, _, _ := newAuthServer(t)
	requireStatus(t, doReqAuth(t, s.Handler(), http.MethodGet, "/v1/health/live", "", ""), http.StatusOK)
	requireStatus(t, doReqAuth(t, s.Handler(), http.MethodGet, "/v1/health/ready", "", ""), http.StatusOK)
}

func TestStaleCookieFallsThroughLoopbackUnauth(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "labmitm.yaml")
	body := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec:\n  management:\n    auth:\n      mode: dev-loopback-unauth\n"
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, err := app.Boot(t.Context(), app.Options{BootstrapPath: cfg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	v, err := auth.FromSpec(svc.Active().Canonical.Spec.Management.Auth)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Service: svc, Auth: v, RatePerSec: -1})
	if err != nil {
		t.Fatal(err)
	}
	req := httptestReq(http.MethodGet, "/v1/flows", "")
	req.Header.Del("Authorization")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: "stale-or-expired"})
	rec := doRaw(s.Handler(), req)
	requireStatus(t, rec, http.StatusOK)
}

func TestReloadAuthKeepsSessionsWhenSecretsUnreadable(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "labmitm.yaml")
	body := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec:\n  management:\n    auth:\n      mode: bearer\n      tokens:\n        - id: admin\n          secretFile: " + tok + "\n          role: administrator\n"
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, err := app.Boot(t.Context(), app.Options{BootstrapPath: cfg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	v, err := auth.FromSpec(svc.Active().Canonical.Spec.Management.Auth)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Service: svc, Auth: v, RatePerSec: -1})
	if err != nil {
		t.Fatal(err)
	}
	req := httptestReq(http.MethodPost, "/v1/session", "")
	rec := doRaw(s.Handler(), req)
	requireStatus(t, rec, http.StatusOK)
	var cookie string
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			cookie = c.Value
		}
	}
	if err := os.Remove(tok); err != nil {
		t.Fatal(err)
	}
	s.reloadAuth()
	get := httptestReq(http.MethodGet, "/v1/session", "")
	get.Header.Del("Authorization")
	get.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	grec := doRaw(s.Handler(), get)
	requireStatus(t, grec, http.StatusOK)
	if decodeJSON(t, grec)["csrf"] == "" {
		t.Fatal("session dropped after failed secret reread")
	}
}

func TestApplyRoleDemotionClearsSessions(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "labmitm.yaml")
	body := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec:\n  management:\n    auth:\n      mode: bearer\n      tokens:\n        - id: admin\n          secretFile: " + tok + "\n          role: administrator\n"
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, err := app.Boot(t.Context(), app.Options{BootstrapPath: cfg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	v, err := auth.FromSpec(svc.Active().Canonical.Spec.Management.Auth)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Service: svc, Auth: v, RatePerSec: -1})
	if err != nil {
		t.Fatal(err)
	}

	req := httptestReq(http.MethodPost, "/v1/session", "")
	rec := doRaw(s.Handler(), req)
	requireStatus(t, rec, http.StatusOK)
	var cookie string
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			cookie = c.Value
		}
	}
	if cookie == "" {
		t.Fatal("missing session cookie")
	}

	// Demote the live spec, then Apply so OnApply (not reloadAuth directly) rebuilds.
	snap := svc.Active()
	if len(snap.Canonical.Spec.Management.Auth.Tokens) != 1 {
		t.Fatal("expected one token")
	}
	snap.Canonical.Spec.Management.Auth.Tokens[0].Role = model.RoleViewer
	snap.Canonical.Spec.Management.Auth.Tokens[0].Scopes = nil

	applyBody, err := json.Marshal(map[string]any{
		"expectedRevision": string(snap.Revision),
		"operations": []map[string]any{{
			"op": "replaceRules",
			"rules": map[string]any{
				"enabled": true,
				"items":   []any{},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	apply := httptestReq(http.MethodPost, "/v1/changes:apply", string(applyBody))
	arec := doRaw(s.Handler(), apply)
	requireStatus(t, arec, http.StatusOK)

	stale := httptestReq(http.MethodGet, "/v1/session", "")
	stale.Header.Del("Authorization")
	stale.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	srec := doRaw(s.Handler(), stale)
	requireProblem(t, srec, http.StatusUnauthorized, "unauthenticated")

	bearer := httptestReq(http.MethodGet, "/v1/session", "")
	brec := doRaw(s.Handler(), bearer)
	requireStatus(t, brec, http.StatusOK)
	if decodeJSON(t, brec)["role"] != model.RoleViewer {
		t.Fatalf("bearer after demotion=%s", brec.Body.String())
	}
}

func TestBasicRejectedOnREST(t *testing.T) {
	s, _, _ := newAuthServer(t)
	req := httptestReq(http.MethodGet, "/v1/session", "")
	req.SetBasicAuth("admin", "lab-web-pass")
	rec := doRaw(s.Handler(), req)
	requireProblem(t, rec, http.StatusUnauthorized, "unauthenticated")
}

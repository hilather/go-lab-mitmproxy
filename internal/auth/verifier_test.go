package auth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

const testToken = "0123456789abcdef0123456789abcdef"

func writeSecret(t *testing.T, dir, name, value string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBearerAuthenticate(t *testing.T) {
	dir := t.TempDir()
	tok := writeSecret(t, dir, "token", testToken)
	v, err := FromSpec(model.MgmtAuthSpec{
		Mode: model.MgmtAuthBearer,
		Tokens: []model.TokenSpec{{
			ID:         "admin",
			SecretFile: tok,
			Role:       model.RoleAdministrator,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RequireListen(); err != nil {
		t.Fatal(err)
	}
	p, err := v.Authenticate(Request{Authorization: "Bearer " + testToken})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "admin" || p.Class != ClassToken || !p.HasScope(model.ScopeMITMAdmin) {
		t.Fatalf("principal %+v", p)
	}
	if _, err := v.Authenticate(Request{}); err == nil {
		t.Fatal("missing Authorization must fail in bearer mode")
	}
	if _, err := v.Authenticate(Request{Authorization: "Bearer wrong-token-0123456789abcdefxx"}); err == nil {
		t.Fatal("wrong token must fail")
	}
	if _, err := v.Authenticate(Request{Authorization: "Basic YWRtaW46eA=="}); err == nil {
		t.Fatal("Basic must not authenticate")
	}
}

func TestMissingTokenFileFailsClosed(t *testing.T) {
	_, err := FromSpec(model.MgmtAuthSpec{
		Mode: model.MgmtAuthBearer,
		Tokens: []model.TokenSpec{{
			ID:         "admin",
			SecretFile: filepath.Join(t.TempDir(), "missing.token"),
			Role:       model.RoleAdministrator,
		}},
	})
	if err == nil {
		t.Fatal("missing secret file must fail")
	}
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeValidationFailed {
		t.Fatalf("err=%v", err)
	}
}

func TestBearerNoTokensRefuseListen(t *testing.T) {
	v, err := FromSpec(model.MgmtAuthSpec{Mode: model.MgmtAuthBearer})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RequireListen(); err == nil {
		t.Fatal("bearer with zero tokens must refuse listen")
	}
}

func TestStaticVerifier(t *testing.T) {
	v := Static(testToken, "admin", model.RoleOperator)
	p, err := v.AuthenticateBearer(testToken)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasScope(model.ScopeMITMWrite) || p.HasScope(model.ScopeMITMAdmin) {
		t.Fatalf("operator scopes %+v", p.Scopes)
	}
}

func TestEquivalentRoleChange(t *testing.T) {
	dir := t.TempDir()
	tok := writeSecret(t, dir, "token", testToken)
	spec := model.MgmtAuthSpec{
		Mode: model.MgmtAuthBearer,
		Tokens: []model.TokenSpec{{
			ID: "admin", SecretFile: tok, Role: model.RoleAdministrator,
		}},
	}
	a, err := FromSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equivalent(b) {
		t.Fatal("identical specs must be equivalent")
	}
	spec.Tokens[0].Role = model.RoleViewer
	spec.Tokens[0].Scopes = nil
	c, err := FromSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if a.Equivalent(c) {
		t.Fatal("role demotion must not be equivalent")
	}
	if got := WWWAuthenticate(); len(got) != 1 || got[0] != `Bearer realm="labmitm"` {
		t.Fatalf("www-authenticate=%v", got)
	}
}

func TestDevLoopbackUnauth(t *testing.T) {
	v, err := FromSpec(model.MgmtAuthSpec{Mode: model.MgmtAuthDevLoopbackUnauth})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RequireListen(); err != nil {
		t.Fatal(err)
	}
	p, err := v.Authenticate(Request{RemoteAddr: "127.0.0.1:9"})
	if err != nil || p.Class != ClassLoopback {
		t.Fatalf("loopback %+v err=%v", p, err)
	}
	if _, err := v.Authenticate(Request{RemoteAddr: "8.8.8.8:9"}); err == nil {
		t.Fatal("non-loopback unauth must fail")
	}
}

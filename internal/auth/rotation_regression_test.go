package auth

import (
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestSessionIssuanceRejectsRotatedPrincipal(t *testing.T) {
	v := Static("old-secret", "admin", model.RoleAdministrator)
	s := NewStore(DefaultSessionConfig())
	v.OnIdentityChange(s.Clear)
	p, err := v.AuthenticateBearer("old-secret")
	if err != nil {
		t.Fatal(err)
	}
	v.Replace(Static("new-secret", "admin", model.RoleViewer))
	cookie, _, _, err := s.Create(p)
	if err == nil {
		t.Fatalf("revoked principal issued cookie %q", cookie)
	}
}

func TestSessionLookupRejectsRotationBeforeClearHook(t *testing.T) {
	v := Static("old-secret", "admin", model.RoleAdministrator)
	s := NewStore(DefaultSessionConfig())
	p, err := v.AuthenticateBearer("old-secret")
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf, _, err := s.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	v.OnIdentityChange(func() {
		if _, _, ok := s.Lookup(cookie); ok {
			t.Error("revoked session accepted before clear hook")
		}
		if s.ValidCSRF(cookie, csrf) {
			t.Error("revoked session CSRF accepted")
		}
		s.Clear()
	})
	v.Replace(Static("new-secret", "admin", model.RoleViewer))
}

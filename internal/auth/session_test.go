package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestSessionCreateAndLookup(t *testing.T) {
	s := NewStore(DefaultSessionConfig())
	if s.cfg.Max != 64 {
		t.Fatalf("default max=%d want 64", s.cfg.Max)
	}
	p := Principal{ID: "admin", Role: model.RoleAdministrator, Scopes: allScopes()}
	cookie, csrf, sess, err := s.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(cookie) < 64 || len(csrf) < 64 || sess.ID == "" {
		t.Fatalf("entropy cookie=%d csrf=%d id=%q", len(cookie), len(csrf), sess.ID)
	}
	if cookie == csrf || cookie == sess.ID {
		t.Fatal("cookie, csrf, and public id must differ")
	}
	got, gotCSRF, ok := s.Lookup(cookie)
	if !ok || got.TokenID != "admin" || gotCSRF != csrf {
		t.Fatalf("lookup %+v %q %v", got, gotCSRF, ok)
	}
}

func TestSessionExpiryAndCSRF(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	s := NewStore(SessionConfig{Idle: time.Minute, Absolute: 5 * time.Minute, Max: 8})
	s.SetClock(func() time.Time { return now })
	cookie, csrf, _, err := s.Create(Principal{ID: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if !s.ValidCSRF(cookie, csrf) || s.ValidCSRF(cookie, "wrong") {
		t.Fatal("csrf compare")
	}
	now = now.Add(61 * time.Second)
	if s.ValidCSRF(cookie, csrf) {
		t.Fatal("expired session csrf accepted")
	}
	if _, _, ok := s.Lookup(cookie); ok {
		t.Fatal("idle expiry should invalidate")
	}
}

func TestSessionMaxEvictsOldest(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	s := NewStore(SessionConfig{Idle: time.Hour, Absolute: 12 * time.Hour, Max: 2})
	s.SetClock(func() time.Time { return now })
	a, _, _, err := s.Create(Principal{ID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	b, _, _, err := s.Create(Principal{ID: "b"})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	c, _, _, err := s.Create(Principal{ID: "c"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Lookup(a); ok {
		t.Fatal("oldest session should be evicted at max 2")
	}
	if _, _, ok := s.Lookup(b); !ok {
		t.Fatal("newer session b dropped")
	}
	if _, _, ok := s.Lookup(c); !ok {
		t.Fatal("newest session c dropped")
	}
}

func TestSessionCookieFlags(t *testing.T) {
	c := NewSessionCookie("abc", false, 0)
	if c.Name != CookieName || c.Path != "/" || !c.HttpOnly {
		t.Fatalf("cookie = %+v", c)
	}
	if c.Name != "labmitm_session" {
		t.Fatalf("cookie name = %q", c.Name)
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("samesite = %v", c.SameSite)
	}
	if c.Secure {
		t.Fatal("secure set on cleartext")
	}
	if !NewSessionCookie("abc", true, 0).Secure {
		t.Fatal("secure not set for TLS")
	}
	clear := ClearSessionCookie(true)
	if clear.MaxAge != -1 || !clear.Secure || !clear.HttpOnly {
		t.Fatalf("clear = %+v", clear)
	}
	if CSRFHeader != "X-LabMITM-CSRF" {
		t.Fatalf("csrf header = %q", CSRFHeader)
	}
}

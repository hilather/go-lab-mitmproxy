package auth

import (
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// Credential classes recorded on Actor and audit events.
const (
	ClassToken    = "token"
	ClassLoopback = "loopback"
)

// Principal is the non-secret actor after authentication.
type Principal struct {
	ID     string
	Class  string
	Role   string
	Scopes []string
}

// HasScope reports whether p grants want. mitm.admin satisfies every scope.
func (p Principal) HasScope(want string) bool {
	return HasScope(p.Scopes, want)
}

// HasScope reports whether scopes grant want. mitm.admin satisfies every scope.
func HasScope(scopes []string, want string) bool {
	if want == "" {
		return true
	}
	for _, s := range scopes {
		if s == model.ScopeMITMAdmin || s == want {
			return true
		}
	}
	return false
}

// Authorize reports forbidden when any required scope is missing.
func Authorize(p Principal, required []string) error {
	return AuthorizeScopes(p.Scopes, required)
}

// AuthorizeScopes is Authorize for an already-copied scope list (app.Actor).
func AuthorizeScopes(scopes []string, required []string) error {
	for _, want := range required {
		if !HasScope(scopes, want) {
			return domainerr.Forbidden("missing scope " + want)
		}
	}
	return nil
}

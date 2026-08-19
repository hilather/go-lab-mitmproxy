package rest

import (
	"net/http"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
)

func (s *Server) handleSessionCreate(w http.ResponseWriter, r *http.Request, instance string, actor app.Actor) {
	// Cookie + CSRF is SEC-001. Catalog row is registered so OpenAPI stays complete.
	s.writeProblem(w, r, instance, domainerr.NotFound("UI session is not available"))
	_ = r
	_ = actor
}

func (s *Server) handleSessionDelete(w http.ResponseWriter, r *http.Request, instance string, actor app.Actor) {
	s.writeProblem(w, r, instance, domainerr.NotFound("UI session is not available"))
	_ = r
	_ = actor
}

func (s *Server) handleSessionGet(w http.ResponseWriter, r *http.Request, instance string, actor app.Actor) {
	out := sessionViewJSON{
		ID:     actor.ID,
		Role:   actor.Role,
		Scopes: actor.Scopes,
	}
	if out.Scopes == nil {
		out.Scopes = []string{}
	}
	s.writeJSON(w, http.StatusOK, out)
	_ = instance
	_ = r
}

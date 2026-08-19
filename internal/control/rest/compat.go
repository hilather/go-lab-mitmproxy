package rest

import (
	"net/http"
	"path"
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
	"github.com/hilather/go-lab-mitmproxy/internal/control/compat"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

const headerTruncated = "X-LabMITM-Truncated"

// serveCompat matches CompatBindings after origin/inflight (not dispatchMount).
// Disabled prefix hits are 404 problem+json so the SPA cannot swallow them.
func (s *Server) serveCompat(w http.ResponseWriter, r *http.Request, instance string, capID *string) bool {
	rt, params, pathOK, methodOK := s.matchCompat(r)
	if !pathOK {
		return false
	}
	if capID != nil {
		*capID = string(rt.cap.ID)
	}
	if !s.compatEnabled() {
		s.writeProblem(w, r, instance, domainerr.NotFound("not found"))
		return true
	}
	if !methodOK {
		w.Header().Set(headerAllow, s.compatAllowedMethods(r.URL.Path))
		s.writeProblem(w, r, instance, domainerr.MethodNotAllowed("method not allowed"))
		return true
	}
	if err := s.rate.allow(r.RemoteAddr); err != nil {
		s.writeProblem(w, r, instance, err)
		return true
	}
	actor, err := s.authenticate(r, false)
	if err != nil {
		s.writeProblem(w, r, instance, err)
		return true
	}
	if err := s.authorize(r, actor, rt.cap); err != nil {
		s.writeProblem(w, r, instance, err)
		return true
	}
	s.compatDispatch(w, r, instance, actor, rt, params)
	return true
}

func (s *Server) compatDispatch(w http.ResponseWriter, r *http.Request, instance string, actor app.Actor, rt compiledRoute, params map[string]string) {
	ctx := r.Context()
	if err := ctx.Err(); err != nil {
		s.writeProblem(w, r, instance, domainerr.Internal("request canceled"))
		return
	}
	switch rt.binding.RESTRef() {
	case compat.RefList:
		items, truncated, err := compat.List(ctx, s.svc, actor)
		if err != nil {
			s.writeProblem(w, r, instance, asDomain(err))
			return
		}
		if truncated {
			w.Header().Set(headerTruncated, "true")
		}
		s.writeJSON(w, http.StatusOK, items)
	case compat.RefGet:
		f, err := compat.Get(ctx, s.svc, actor, params["id"])
		if err != nil {
			s.writeProblem(w, r, instance, asDomain(err))
			return
		}
		s.writeJSON(w, http.StatusOK, f)
	case compat.RefDelete:
		if err := compat.Delete(ctx, s.svc, actor, params["id"]); err != nil {
			s.writeProblem(w, r, instance, asDomain(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case compat.RefClear:
		if err := compat.Clear(ctx, s.svc, actor); err != nil {
			s.writeProblem(w, r, instance, asDomain(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case compat.RefReplay:
		f, err := compat.Replay(ctx, s.svc, actor, params["id"])
		if err != nil {
			s.writeProblem(w, r, instance, asDomain(err))
			return
		}
		s.writeJSON(w, http.StatusOK, f)
	case compat.RefRequestContent:
		s.handleFlowBody(w, r, instance, ctx, actor, params["id"], true)
	case compat.RefResponseContent:
		s.handleFlowBody(w, r, instance, ctx, actor, params["id"], false)
	default:
		s.writeProblem(w, r, instance, domainerr.NotFound("not found"))
	}
}

func (s *Server) matchCompat(r *http.Request) (compiledRoute, map[string]string, bool, bool) {
	matchPath := s.compatMatchPath(r.URL.Path)
	if matchPath == "" {
		return compiledRoute{}, nil, false, false
	}
	return matchRoute(s.compatRoutes, r.Method, matchPath)
}

func (s *Server) compatAllowedMethods(reqPath string) string {
	matchPath := s.compatMatchPath(reqPath)
	if matchPath == "" {
		return ""
	}
	return allowedMethods(s.compatRoutes, matchPath)
}

func (s *Server) compatMatchPath(reqPath string) string {
	_, prefix := s.liveFlowREST()
	if !pathIsUnder(reqPath, prefix) {
		return ""
	}
	if prefix == capabilities.DefaultCompatPathPrefix {
		return reqPath
	}
	trimmed := strings.TrimPrefix(reqPath, prefix)
	if trimmed == "" {
		return capabilities.DefaultCompatPathPrefix
	}
	return capabilities.DefaultCompatPathPrefix + trimmed
}

func (s *Server) compatEnabled() bool {
	enabled, _ := s.liveFlowREST()
	return enabled
}

func (s *Server) liveFlowREST() (enabled bool, prefix string) {
	prefix = capabilities.DefaultCompatPathPrefix
	sp := s.liveSpec()
	if sp == nil {
		return false, prefix
	}
	fr := sp.Compat.FlowREST
	if p := strings.TrimSpace(fr.PathPrefix); p != "" {
		prefix = p
	}
	return fr.Enabled, prefix
}

func (s *Server) liveSpec() *model.Spec {
	appSvc, ok := s.svc.(*app.App)
	if !ok || appSvc == nil {
		return nil
	}
	snap := appSvc.Active()
	if snap == nil || snap.Canonical == nil {
		return nil
	}
	return &snap.Canonical.Spec
}

func (s *Server) liveManagementPaths() (restPath, mcpPath, compatPrefix string) {
	restPath = "/v1"
	mcpPath = "/mcp"
	compatPrefix = capabilities.DefaultCompatPathPrefix
	sp := s.liveSpec()
	if sp == nil {
		return restPath, mcpPath, compatPrefix
	}
	if p := strings.TrimSpace(sp.Listeners.Management.RESTPath); p != "" {
		restPath = p
	}
	if p := strings.TrimSpace(sp.Listeners.Management.MCPPath); p != "" {
		mcpPath = p
	}
	if p := strings.TrimSpace(sp.Compat.FlowREST.PathPrefix); p != "" {
		compatPrefix = p
	}
	return restPath, mcpPath, compatPrefix
}

func pathIsUnder(p, prefix string) bool {
	p = path.Clean("/" + p)
	prefix = path.Clean("/" + prefix)
	if prefix == "/" {
		return p == "/"
	}
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

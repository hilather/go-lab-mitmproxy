package rest

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

func (s *Server) handleListFlows(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	q, err := listQueryFromRequest(r)
	if err != nil {
		s.writeProblem(w, r, instance, err)
		return
	}
	rawCursor := q.Cursor
	var cursorGen uint64
	if rawCursor != "" {
		id, gen, err := s.decodeCursor(rawCursor)
		if err != nil {
			s.writeProblem(w, r, instance, err)
			return
		}
		q.Cursor = id
		cursorGen = gen
	}
	res, err := s.svc.ListFlows(ctx, actor, q)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	if rawCursor != "" && cursorGen != res.Generation {
		s.writeProblem(w, r, instance, domainerr.CursorStale("list cursor is stale; restart the list"))
		return
	}
	items := make([]flowJSON, 0, len(res.Items))
	for _, f := range res.Items {
		items = append(items, fromFlow(f, true))
	}
	var next *string
	if res.NextCursor != "" {
		enc := s.encodeCursor(res.NextCursor, res.Generation)
		next = &enc
	}
	rev := ""
	if st, err := s.svc.GetState(ctx, actor); err == nil && st != nil {
		rev = string(st.RuntimeRevision)
	}
	s.writeJSON(w, http.StatusOK, flowListJSON{
		Revision:        rev,
		StoreGeneration: res.Generation,
		Items:           items,
		NextCursor:      next,
	})
}

func listQueryFromRequest(r *http.Request) (model.ListQuery, error) {
	qs := r.URL.Query()
	q := model.ListQuery{
		Filter: model.FlowFilter{
			Host:       qs.Get("host"),
			Method:     qs.Get("method"),
			Scheme:     qs.Get("scheme"),
			RuleID:     qs.Get("ruleId"),
			PathPrefix: qs.Get("pathPrefix"),
			Protocol:   qs.Get("protocol"),
			Via:        qs.Get("via"),
		},
		Cursor: qs.Get("cursor"),
	}
	if raw := qs.Get("intercepted"); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return q, domainerr.ValidationFailed("invalid intercepted",
				domainerr.FieldViolation{Path: "intercepted", Code: "invalid_value", Message: "intercepted must be true or false"})
		}
		q.Filter.Intercepted = &b
	}
	if raw := qs.Get("status"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return q, domainerr.ValidationFailed("invalid status",
				domainerr.FieldViolation{Path: "status", Code: "invalid_value", Message: "status must be a non-negative integer"})
		}
		q.Filter.Status = n
	}
	if raw := qs.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return q, domainerr.ValidationFailed("invalid limit",
				domainerr.FieldViolation{Path: "limit", Code: "invalid_value", Message: "limit must be a non-negative integer"})
		}
		q.Limit = n
	}
	return q, nil
}

func (s *Server) handleGetFlow(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor, id string) {
	f, err := s.svc.GetFlow(ctx, actor, id)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, fromFlow(f, false))
	_ = r
}

func (s *Server) handleFlowBody(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor, id string, request bool) {
	f, err := s.svc.GetFlow(ctx, actor, id)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	side := f.Response
	name := "response"
	if request {
		side = f.Request
		name = "request"
	}
	// Never reflect captured Content-Type. A browser GET of text/html
	// or image/svg+xml would execute scripts on the management origin.
	w.Header().Set("Content-Disposition", `attachment; filename="`+flowBodyFilename(id, name)+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	s.writeBytes(w, http.StatusOK, "application/octet-stream", side.Body)
	_ = r
}

func flowBodyFilename(id, side string) string {
	return "flow-" + sanitizeDownloadName(id) + "-" + sanitizeDownloadName(side) + ".bin"
}

func sanitizeDownloadName(name string) string {
	name = strings.ReplaceAll(name, `"`, "")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "\r", "")
	name = strings.ReplaceAll(name, "\n", "")
	if name == "" {
		return "body"
	}
	return name
}

func (s *Server) handleDeleteFlow(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor, id string) {
	in, err := s.deleteIn(w, r, instance)
	if err != nil {
		return
	}
	if err := s.svc.DeleteFlow(ctx, actor, id, in); err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleClear(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	in, err := s.deleteIn(w, r, instance)
	if err != nil {
		return
	}
	n, err := s.svc.ClearFlows(ctx, actor, in)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"deleted": n})
}

func (s *Server) deleteIn(w http.ResponseWriter, r *http.Request, instance string) (app.DeleteIn, error) {
	var body deleteRequest
	if r.ContentLength != 0 && r.Header.Get("Content-Type") != "" {
		if !s.decodeJSONOptional(w, r, instance, &body) {
			return app.DeleteIn{}, domainerr.ValidationFailed("invalid body")
		}
	}
	if body.ExpectedStoreGeneration == nil {
		if raw := r.URL.Query().Get("expectedStoreGeneration"); raw != "" {
			n, err := parseStoreGeneration(raw)
			if err != nil {
				s.writeProblem(w, r, instance, err)
				return app.DeleteIn{}, err
			}
			body.ExpectedStoreGeneration = &n
		}
	}
	if body.ExpectedStoreGeneration == nil {
		if raw := strings.Trim(r.Header.Get(headerIfMatch), `"`); raw != "" && !strings.EqualFold(raw, "*") {
			n, err := parseStoreGeneration(raw)
			if err != nil {
				s.writeProblem(w, r, instance, err)
				return app.DeleteIn{}, err
			}
			body.ExpectedStoreGeneration = &n
		}
	}
	return app.DeleteIn{ExpectedStoreGeneration: body.ExpectedStoreGeneration}, nil
}

func parseStoreGeneration(raw string) (uint64, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, domainerr.ValidationFailed("invalid expectedStoreGeneration",
			domainerr.FieldViolation{Path: "expectedStoreGeneration", Code: "invalid_value", Message: "expectedStoreGeneration must be an integer"})
	}
	return n, nil
}

func (s *Server) handleWait(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	var in waitRequest
	if !s.decodeJSON(w, r, instance, &in) {
		return
	}
	filter := model.FlowFilter{
		Host:        in.Filter.Host,
		Method:      in.Filter.Method,
		PathPrefix:  in.Filter.PathPrefix,
		Intercepted: in.Filter.Intercepted,
		Protocol:    in.Filter.Protocol,
		Via:         in.Filter.Via,
	}
	if in.Filter.Status != nil {
		filter.Status = *in.Filter.Status
	}
	after, err := parseOptionalTime(in.Filter.After, "filter.after")
	if err != nil {
		s.writeProblem(w, r, instance, err)
		return
	}
	filter.After = after
	if in.Timeout < 0 {
		s.writeProblem(w, r, instance, domainerr.ValidationFailed("invalid timeout",
			domainerr.FieldViolation{Path: "timeout", Code: "invalid_value", Message: "timeout must use Go duration syntax"}))
		return
	}
	f, err := s.svc.Wait(ctx, actor, app.WaitIn{Filter: filter, Timeout: in.Timeout})
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, fromFlow(f, false))
}

func parseOptionalTime(raw, field string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, raw)
	}
	if err != nil {
		return time.Time{}, domainerr.ValidationFailed("invalid timestamp",
			domainerr.FieldViolation{Path: field, Code: "invalid_value", Message: field + " must be RFC3339"})
	}
	return t.UTC(), nil
}

func (s *Server) handleResume(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor, id string) {
	var in resumeRequest
	if !s.decodeJSONOptional(w, r, instance, &in) {
		return
	}
	var patch *store.ResumePatch
	if in.Headers != nil || in.Body != nil {
		p := store.ResumePatch{}
		if in.Headers != nil {
			p.Headers = *in.Headers
		}
		if in.Body != nil {
			p.Body = []byte(*in.Body)
		}
		patch = &p
	}
	if err := s.svc.Resume(ctx, actor, id, patch); err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDrop(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor, id string) {
	if err := s.svc.Drop(ctx, actor, id); err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
	_ = r
}

func (s *Server) handleReplay(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor, id string) {
	f, err := s.svc.Replay(ctx, actor, id)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, fromFlow(f, false))
	_ = r
}

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/buildinfo"
	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func (s *Server) registerTools() {
	addTool(s, "mitm_version_get", versionDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		_ = actor
		return fromVersion(buildinfo.Current()), nil
	})
	addTool(s, "mitm_capabilities_get", capDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		_ = actor
		return fromCapabilities(), nil
	})
	addTool(s, "mitm_status_get", statusDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		return s.statusDTO(ctx, actor)
	})
	addTool(s, "mitm_schema_get", schemaDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		_ = actor
		b, err := config.SchemaBytes()
		if err != nil {
			return nil, domainerr.Internal("schema unavailable")
		}
		var doc any
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, domainerr.Internal("internal error")
		}
		return doc, nil
	})
	addTool(s, "mitm_state_get", stateGetDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		v, err := s.svc.GetState(ctx, actor)
		if err != nil {
			return nil, err
		}
		return fromStateView(v)
	})
	addTool(s, "mitm_state_validate", validateDesc, false, true, func(ctx context.Context, actor app.Actor, in validateIn) (any, error) {
		vin, err := in.toValidate()
		if err != nil {
			return nil, asDomain(err)
		}
		p, err := s.svc.Validate(ctx, actor, vin)
		if err != nil {
			return nil, err
		}
		return fromPlan(p), nil
	})
	addTool(s, "mitm_change_plan", planDesc, false, true, func(ctx context.Context, actor app.Actor, in changeIn) (any, error) {
		p, err := s.svc.Plan(ctx, actor, in.toChange())
		if err != nil {
			return nil, err
		}
		return fromPlan(p), nil
	})
	addTool(s, "mitm_change_apply", applyDesc, true, true, func(ctx context.Context, actor app.Actor, in changeIn) (any, error) {
		r, err := s.svc.Apply(ctx, actor, in.toChange())
		if err != nil {
			return nil, err
		}
		return fromApply(r), nil
	})
	addTool(s, "mitm_state_export", exportDesc, false, true, func(ctx context.Context, actor app.Actor, in exportIn) (any, error) {
		format := app.ExportYAML
		switch strings.ToLower(in.Format) {
		case "", "yaml", "yml":
		case "json":
			format = app.ExportJSON
		default:
			return nil, domainerr.ValidationFailed("unknown export format",
				domainerr.FieldViolation{Path: "format", Code: "invalid_value", Message: "format must be yaml or json"})
		}
		exp, err := s.svc.Export(ctx, actor, format)
		if err != nil {
			return nil, err
		}
		return fromExport(exp), nil
	})
	addTool(s, "mitm_state_reset", resetDesc, true, false, func(ctx context.Context, actor app.Actor, in resetIn) (any, error) {
		r, err := s.svc.Reset(ctx, actor, app.ResetIn{Reason: in.Reason})
		if err != nil {
			return nil, err
		}
		return fromApply(r), nil
	})
	addTool(s, "mitm_flows_list", flowsListDesc, false, true, func(ctx context.Context, actor app.Actor, in listIn) (any, error) {
		return s.listFlows(ctx, actor, in)
	})
	addTool(s, "mitm_flow_get", flowGetDesc, false, true, func(ctx context.Context, actor app.Actor, in idIn) (any, error) {
		if in.ID == "" {
			return nil, domainerr.ValidationFailed("id is required",
				domainerr.FieldViolation{Path: "id", Code: "required", Message: "id is required"})
		}
		f, err := s.svc.GetFlow(ctx, actor, in.ID)
		if err != nil {
			return nil, err
		}
		return fromFlow(f, false), nil
	})
	addTool(s, "mitm_flow_request_get", flowRequestDesc, false, true, func(ctx context.Context, actor app.Actor, in idIn) (any, error) {
		return s.flowBody(ctx, actor, in.ID, true)
	})
	addTool(s, "mitm_flow_response_get", flowResponseDesc, false, true, func(ctx context.Context, actor app.Actor, in idIn) (any, error) {
		return s.flowBody(ctx, actor, in.ID, false)
	})
	addTool(s, "mitm_flow_delete", flowDeleteDesc, true, true, func(ctx context.Context, actor app.Actor, in deleteIn) (any, error) {
		if in.ID == "" {
			return nil, domainerr.ValidationFailed("id is required",
				domainerr.FieldViolation{Path: "id", Code: "required", Message: "id is required"})
		}
		if err := s.svc.DeleteFlow(ctx, actor, in.ID, app.DeleteIn{ExpectedStoreGeneration: in.ExpectedStoreGeneration}); err != nil {
			return nil, err
		}
		return okJSON{OK: true}, nil
	})
	addTool(s, "mitm_flows_clear", flowsClearDesc, true, true, func(ctx context.Context, actor app.Actor, in clearIn) (any, error) {
		n, err := s.svc.ClearFlows(ctx, actor, app.DeleteIn{ExpectedStoreGeneration: in.ExpectedStoreGeneration})
		if err != nil {
			return nil, err
		}
		return countJSON{Deleted: n}, nil
	})
	addTool(s, "mitm_flows_wait", flowsWaitDesc, false, true, func(ctx context.Context, actor app.Actor, in waitIn) (any, error) {
		win, err := in.toWait()
		if err != nil {
			return nil, err
		}
		f, err := s.svc.Wait(ctx, actor, win)
		if err != nil {
			return nil, err
		}
		return fromFlow(f, false), nil
	})
	addTool(s, "mitm_flow_resume", flowResumeDesc, true, true, func(ctx context.Context, actor app.Actor, in resumeIn) (any, error) {
		if in.ID == "" {
			return nil, domainerr.ValidationFailed("id is required",
				domainerr.FieldViolation{Path: "id", Code: "required", Message: "id is required"})
		}
		if err := s.svc.Resume(ctx, actor, in.ID, in.toPatch()); err != nil {
			return nil, err
		}
		return okJSON{OK: true}, nil
	})
	addTool(s, "mitm_flow_drop", flowDropDesc, true, true, func(ctx context.Context, actor app.Actor, in idIn) (any, error) {
		if in.ID == "" {
			return nil, domainerr.ValidationFailed("id is required",
				domainerr.FieldViolation{Path: "id", Code: "required", Message: "id is required"})
		}
		if err := s.svc.Drop(ctx, actor, in.ID); err != nil {
			return nil, err
		}
		return okJSON{OK: true}, nil
	})
	addTool(s, "mitm_flow_replay", flowReplayDesc, true, false, func(ctx context.Context, actor app.Actor, in idIn) (any, error) {
		if in.ID == "" {
			return nil, domainerr.ValidationFailed("id is required",
				domainerr.FieldViolation{Path: "id", Code: "required", Message: "id is required"})
		}
		f, err := s.svc.Replay(ctx, actor, in.ID)
		if err != nil {
			return nil, err
		}
		return fromFlow(f, false), nil
	})
	addTool(s, "mitm_ca_get", caGetDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		pem, err := s.svc.GetCA(ctx, actor)
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(pem), "PRIVATE KEY") {
			return nil, domainerr.Internal("CA private key must never be exported")
		}
		return caPEMJSON{PEM: string(pem), ContentType: "application/x-pem-file"}, nil
	})
	addTool(s, "mitm_audit_query", auditQueryDesc, false, true, func(ctx context.Context, actor app.Actor, in auditQueryIn) (any, error) {
		list, err := s.svc.QueryAudit(ctx, actor, app.AuditQuery{Limit: in.Limit})
		if err != nil {
			return nil, err
		}
		return fromAuditList(list), nil
	})
	addTool(s, "mitm_audit_get", auditGetDesc, false, true, func(ctx context.Context, actor app.Actor, in idIn) (any, error) {
		if in.ID == "" {
			return nil, domainerr.ValidationFailed("id is required",
				domainerr.FieldViolation{Path: "id", Code: "required", Message: "id is required"})
		}
		return s.svc.GetAudit(ctx, actor, in.ID)
	})
}

func (s *Server) statusDTO(ctx context.Context, actor app.Actor) (statusJSON, error) {
	st, err := s.svc.Status(ctx, actor)
	if err != nil {
		return statusJSON{}, err
	}
	view, err := s.svc.GetState(ctx, actor)
	if err != nil {
		return statusJSON{}, err
	}
	return fromStatus(st, view)
}

func (s *Server) listFlows(ctx context.Context, actor app.Actor, in listIn) (flowListJSON, error) {
	filter, err := in.filter()
	if err != nil {
		return flowListJSON{}, err
	}
	q := model.ListQuery{Filter: filter, Cursor: in.Cursor, Limit: in.Limit}
	rawCursor := q.Cursor
	var cursorGen uint64
	if rawCursor != "" {
		id, gen, err := s.decodeCursor(rawCursor)
		if err != nil {
			return flowListJSON{}, err
		}
		q.Cursor = id
		cursorGen = gen
	}
	res, err := s.svc.ListFlows(ctx, actor, q)
	if err != nil {
		return flowListJSON{}, err
	}
	if rawCursor != "" && cursorGen != res.Generation {
		return flowListJSON{}, domainerr.CursorStale("list cursor is stale; restart the list")
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
	return flowListJSON{
		Revision:        rev,
		StoreGeneration: res.Generation,
		Items:           items,
		NextCursor:      next,
	}, nil
}

func (s *Server) flowBody(ctx context.Context, actor app.Actor, id string, request bool) (any, error) {
	if id == "" {
		return nil, domainerr.ValidationFailed("id is required",
			domainerr.FieldViolation{Path: "id", Code: "required", Message: "id is required"})
	}
	f, err := s.svc.GetFlow(ctx, actor, id)
	if err != nil {
		return nil, err
	}
	return rawSide(f, request), nil
}

func addTool[In any](s *Server, name, desc string, mutating, idempotent bool, h func(context.Context, app.Actor, In) (any, error)) {
	caps := capabilities.LookupTool(name)
	title := name
	if len(caps) > 0 && caps[0].Title != "" {
		title = caps[0].Title
		if desc == "" {
			desc = caps[0].Description
		}
	}
	readOnly := !mutating
	ann := &sdk.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    readOnly,
		IdempotentHint:  idempotent,
		DestructiveHint: boolPtr(mutating && !idempotent),
		OpenWorldHint:   boolPtr(false),
	}
	sdk.AddTool(s.sdk, &sdk.Tool{
		Name:        name,
		Title:       title,
		Description: desc,
		Annotations: ann,
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in In) (*sdk.CallToolResult, any, error) {
		if err := ctx.Err(); err != nil {
			return toolErrorResult(canceledError(err)), nil, nil
		}
		actor := s.actorFrom(ctx)
		if err := s.authorizeTool(actor, name); err != nil {
			return toolErrorResult(err), nil, nil
		}
		out, err := h(ctx, actor, in)
		if err != nil {
			return toolErrorResult(err), nil, nil
		}
		structured, err := asStructured(out)
		if err != nil {
			return nil, nil, rpcError(domainerr.Internal("internal error"))
		}
		return nil, structured, nil
	})
}

func boolPtr(v bool) *bool { return &v }

func canceledError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return domainerr.Timeout("request deadline exceeded")
	}
	return domainerr.Internal("request canceled")
}

const (
	versionDesc      = "Read-only. Build and protocol versions (MCP " + ProtocolVersion + ")."
	capDesc          = "Read-only. Capability list and protocol metadata."
	statusDesc       = "Read-only. Listeners, store stats, revisions, intercept, and CA metadata (never the key)."
	schemaDesc       = "Read-only. Published v1alpha1 config JSON Schema."
	stateGetDesc     = "Read-only. Redacted spec plus revision metadata."
	validateDesc     = "Read-only dry-run. Validate a candidate document and/or operations without writing."
	planDesc         = "Read-only dry-run. Plan operations against the active snapshot."
	applyDesc        = "State-changing. Apply operations with expectedRevision. High-impact."
	exportDesc       = "Read-only. Canonical desired-state export plus drift material."
	resetDesc        = "State-changing, high-impact. Reread the bootstrap mount, wipe flows, and swap. Never writes the file."
	flowsListDesc    = "Read-only. Cursor-paginated flow list. HMAC cursors bind storeGeneration."
	flowGetDesc      = "Read-only. One flow including headers and truncated bodies."
	flowRequestDesc  = "Read-only. Captured request body bytes."
	flowResponseDesc = "Read-only. Captured response body bytes."
	flowDeleteDesc   = "State-changing. Delete one flow by id."
	flowsClearDesc   = "State-changing. Delete every flow. Does not bump epoch."
	flowsWaitDesc    = "Read-only. Block until a matching flow arrives or the timeout fires."
	flowResumeDesc   = "State-changing. Resume a paused breakpoint. Optional header/body patch."
	flowDropDesc     = "State-changing. Drop a paused breakpoint."
	flowReplayDesc   = "State-changing. Replay a stored request to the origin (never hairpins the proxy)."
	caGetDesc        = "Read-only. Lab CA PEM certificate only. Never the private key."
	auditQueryDesc   = "Read-only. Query recent in-memory audit events."
	auditGetDesc     = "Read-only. Get one audit event by id."
)

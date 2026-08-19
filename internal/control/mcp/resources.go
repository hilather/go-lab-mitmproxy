package mcp

import (
	"context"
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func (s *Server) registerResources() {
	h := s.readResource
	s.sdk.AddResource(&sdk.Resource{
		URI: "labmitm://capabilities", Name: "capabilities",
		Description: "Capability list and protocol metadata.",
		MIMEType:    "application/json",
	}, h)
	s.sdk.AddResource(&sdk.Resource{
		URI: "labmitm://status", Name: "status",
		Description: "Listeners, store stats, revisions, intercept, and CA metadata.",
		MIMEType:    "application/json",
	}, h)
	s.sdk.AddResource(&sdk.Resource{
		URI: "labmitm://schema/config", Name: "schema-config",
		Description: "Published v1alpha1 config JSON Schema.",
		MIMEType:    "application/schema+json",
	}, h)
	s.sdk.AddResource(&sdk.Resource{
		URI: "labmitm://state", Name: "state",
		Description: "Redacted spec plus revision metadata (same as GET /v1/state).",
		MIMEType:    "application/json",
	}, h)
	s.sdk.AddResource(&sdk.Resource{
		URI: resourceFlows, Name: "flows",
		Description: "Cursor-paginated flow list. subscriptions/listen notifies URI only.",
		MIMEType:    "application/json",
	}, h)
	s.sdk.AddResourceTemplate(&sdk.ResourceTemplate{
		URITemplate: "labmitm://flows/{id}", Name: "flow",
		Description: "One flow by id, including headers and truncated bodies.",
		MIMEType:    "application/json",
	}, h)
	s.sdk.AddResource(&sdk.Resource{
		URI: "labmitm://ca", Name: "ca",
		Description: "Lab CA PEM certificate only. Never the private key.",
		MIMEType:    "application/x-pem-file",
	}, h)
	s.sdk.AddResource(&sdk.Resource{
		URI: "labmitm://audit/recent", Name: "audit-recent",
		Description: "Recent in-memory audit events.",
		MIMEType:    "application/json",
	}, h)
}

func (s *Server) readResource(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, rpcError(domainerr.Internal("request canceled"))
	}
	actor := s.actorFrom(ctx)
	uri := ""
	if req != nil && req.Params != nil {
		uri = req.Params.URI
	}
	if err := s.authorizeResource(actor, uri); err != nil {
		return nil, rpcError(err)
	}
	body, mime, err := s.resourceBody(ctx, actor, uri)
	if err != nil {
		return nil, rpcError(err)
	}
	return &sdk.ReadResourceResult{
		Contents: []*sdk.ResourceContents{{
			URI:      uri,
			MIMEType: mime,
			Text:     string(body),
		}},
	}, nil
}

func (s *Server) resourceBody(ctx context.Context, actor app.Actor, uri string) ([]byte, string, error) {
	switch {
	case uri == "labmitm://capabilities":
		b, err := marshalAPI(fromCapabilities())
		return b, "application/json", err
	case uri == "labmitm://status":
		st, err := s.statusDTO(ctx, actor)
		if err != nil {
			return nil, "", err
		}
		b, err := marshalAPI(st)
		return b, "application/json", err
	case uri == "labmitm://schema/config":
		b, err := config.SchemaBytes()
		return b, "application/schema+json", err
	case uri == "labmitm://state":
		v, err := s.svc.GetState(ctx, actor)
		if err != nil {
			return nil, "", err
		}
		view, err := fromStateView(v)
		if err != nil {
			return nil, "", err
		}
		b, err := marshalAPI(view)
		return b, "application/json", err
	case uri == resourceFlows:
		list, err := s.listFlows(ctx, actor, listIn{})
		if err != nil {
			return nil, "", err
		}
		b, err := marshalAPI(list)
		return b, "application/json", err
	case strings.HasPrefix(uri, "labmitm://flows/"):
		id := strings.TrimPrefix(uri, "labmitm://flows/")
		if id == "" || strings.Contains(id, "/") {
			return nil, "", domainerr.NotFound("resource not found")
		}
		f, err := s.svc.GetFlow(ctx, actor, id)
		if err != nil {
			return nil, "", err
		}
		b, err := marshalAPI(fromFlow(f, false))
		return b, "application/json", err
	case uri == "labmitm://ca":
		pem, err := s.svc.GetCA(ctx, actor)
		if err != nil {
			return nil, "", err
		}
		if strings.Contains(string(pem), "PRIVATE KEY") {
			return nil, "", domainerr.Internal("CA private key must never be exported")
		}
		return pem, "application/x-pem-file", nil
	case uri == "labmitm://audit/recent":
		v, err := s.svc.QueryAudit(ctx, actor, app.AuditQuery{})
		if err != nil {
			return nil, "", err
		}
		b, err := marshalAPI(fromAuditList(v))
		return b, "application/json", err
	default:
		return nil, "", domainerr.NotFound("resource not found")
	}
}

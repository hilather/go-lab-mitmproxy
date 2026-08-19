package mcp

import (
	"context"
	"net/http"
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// validateProtocolVersion pins first GA to 2026-07-28. Older SDK revisions
// still speak 2025-11-25; claiming them would violate ADR 0006 unless
// allowLegacyClients is set (checked by the HTTP adapter).
func validateProtocolVersion(r *http.Request) error {
	ver := strings.TrimSpace(r.Header.Get(headerProtocolVersion))
	if ver == "" {
		return domainerr.ValidationFailed("MCP-Protocol-Version is required; only "+ProtocolVersion+" is supported",
			domainerr.FieldViolation{Path: "MCP-Protocol-Version", Code: "required", Message: "only " + ProtocolVersion + " is supported"})
	}
	if ver != ProtocolVersion {
		return domainerr.ValidationFailed("unsupported MCP protocol version "+ver+"; only "+ProtocolVersion+" is supported",
			domainerr.FieldViolation{Path: "MCP-Protocol-Version", Code: "invalid_value", Message: "only " + ProtocolVersion + " is supported"})
	}
	return nil
}

// pinProtocolMiddleware keeps discover/_meta on the first-GA pin. The SDK
// transport otherwise advertises every version it can speak.
func pinProtocolMiddleware(next sdk.MethodHandler) sdk.MethodHandler {
	return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
		if sr, ok := req.(interface{ ProtocolVersion() string }); ok {
			if v := sr.ProtocolVersion(); v != "" && v != ProtocolVersion {
				return nil, rpcError(domainerr.ValidationFailed("unsupported MCP protocol version "+v+"; only "+ProtocolVersion+" is supported",
					domainerr.FieldViolation{Path: "protocolVersion", Code: "invalid_value", Message: "only " + ProtocolVersion + " is supported"}))
			}
		}
		res, err := next(ctx, method, req)
		if err != nil {
			return nil, err
		}
		if dr, ok := res.(*sdk.DiscoverResult); ok && dr != nil {
			dr.SupportedVersions = []string{ProtocolVersion}
		}
		return res, nil
	}
}

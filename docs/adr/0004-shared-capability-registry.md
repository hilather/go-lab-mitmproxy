# ADR 0004: Shared capability registry for REST and MCP

Status: Accepted
Date: 2026-08-18
Decisions: D4

## Context

Independent adapters tend to drift in schema, defaults, authorization, errors, and audit behavior. `mcp-integration-lab` AGENTS.md rule 8 requires new services to expose MCP. LabDNS / LabMail ADR 0004 already closed this for the family.

## Decision

**D4 — REST and MCP share one capability registry.**

- Declare every public application capability once in `internal/capabilities`.
- Bind REST (`internal/control/rest`) and MCP (`internal/control/mcp`) as adapters over `internal/app.Service`.
- Adapters never call each other and never contain proxy/store business logic.
- Generate `api/capabilities/v1.json`, `api/openapi/v1.json`, `api/mcp/v1.json` from the registry.
- Frozen IDs, paths, tools, and scopes live in [docs/07-control-plane-and-parity.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/07-control-plane-and-parity.md).

## Consequences

- Strong semantic parity.
- Shared authorization and mutation semantics.
- Transport-specific envelopes remain in adapters (`REST_ONLY_PROTOCOL`, `PARITY_DIFFERENT_BINDING`).
- Proxy insert stays on the data plane, not the capability registry.

## Alternatives considered

- REST-first with MCP proxying HTTP: simple but loses native MCP schemas/resources and complicates auth/error mapping.
- Independent implementations: rejected due to drift risk.
- Skip MCP until a later release: rejected by family rule 8.

## Review triggers

Review this decision when its assumptions no longer hold, a major protocol or library change occurs, or a new requirement conflicts with an invariant.

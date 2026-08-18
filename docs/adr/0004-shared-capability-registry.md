# ADR 0004: Shared capability registry for REST and MCP

Status: Accepted
Date: 2026-08-18
Decisions: D4

## Context

Independent adapters drift. mitmweb has REST and no MCP. mcp-integration-lab AGENTS.md rule 8: new services expose MCP. The user requirement is **feature-level REST/MCP parity for every public control**.

## Decision

Declare every public application capability once in `internal/capabilities`. Bind REST and MCP as adapters over `internal/app.Service`. The mitmweb compat adapter also calls `app.Service`. Adapters never call each other. Generate OpenAPI, MCP manifest, and capability JSON from the registry. Frozen IDs live in `docs/05-control-plane-and-parity.md`.

## Consequences

- Strong semantic parity; `make test-parity` is required CI after MCP-001.
- Transport-specific envelopes remain (`REST_ONLY_PROTOCOL`, `PARITY_DIFFERENT_BINDING`).

## Alternatives considered

- REST-first with MCP proxying HTTP: rejected (auth/error/resource drift).
- Independent implementations: rejected.
- MCP-only: rejected (UI and curl operators need REST).

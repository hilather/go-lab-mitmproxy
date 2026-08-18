# MCP-001: MCP Control Plane and Parity

Status: not-started
Recommended owner: MCP agent
Dependencies: API-001
Exclusive ownership: `internal/control/mcp`, `api/mcp/v1.json`, `make test-parity`
Wave: 6 (parallel with COMPAT-001)

## Goal

Streamable HTTP `POST /mcp` with official SDK v1.7.0, protocol `2026-07-28`, every `PARITY_REQUIRED` tool, `labmitm://` resources, `labmitm mcp-stdio`.

## Design references

- [ ] `docs/07-mcp-api.md`
- [ ] `docs/05-control-plane-and-parity.md`
- [ ] ADR 0004, 0006

## Scope

- [ ] Stateless Streamable HTTP.
- [ ] Bearer auth hook compatible with SEC-001.
- [ ] `allowLegacyClients` knob.
- [ ] `make test-parity` walks registry.
- [ ] subscriptions/listen on `labmitm://flows`.

## Required tests

- [ ] Initialize 2026-07-28.
- [ ] tools/list contains frozen `mitm_*` names.
- [ ] **Integration:** tool `mitm_flows_wait` after proxy GET.
- [ ] Parity: each PARITY_REQUIRED capability same side effects REST vs MCP.
- [ ] Origin missing allowed; non-loopback Origin denied.

## Acceptance criteria

- `make test-parity` is a required CI job.
- No REST-only business logic in MCP.

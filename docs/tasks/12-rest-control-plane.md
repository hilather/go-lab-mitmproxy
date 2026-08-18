# API-001: REST Control Plane

Status: not-started
Recommended owner: REST/API agent
Dependencies: STA-001
Exclusive ownership: `internal/capabilities`, `internal/control/rest`, OpenAPI generation
Wave: 6

## Goal

Expose every 1.0 capability that exists in `app.Service` through `/v1` with problem+json. **Own the capability registry freeze** for MCP-001.

## Design references

- [ ] `docs/05-control-plane-and-parity.md`
- [ ] `docs/06-rest-api.md`
- [ ] `docs/17-error-model.md`
- [ ] ADR 0004

## Scope

- [ ] Register all capability rows (stubs returning `unsupported_capability` only if Service method truly missing — prefer complete Service coverage; missing methods block this PR).
- [ ] Health, version, capabilities, state, plan/apply, flows CRUD/wait/dump/har, intercept, view, commands, scripts (may 501 until SCRIPT-001 — **forbidden**: 501 on a PARITY_REQUIRED row unless the program board records SCRIPT as later; scripts can be empty list until SCRIPT-001).
- [ ] Cursor pagination, rate limits, body limits.
- [ ] `make generate` OpenAPI + capabilities JSON.
- [ ] Session routes may 501 until SEC-001 but then UI blocks; implement unauthenticated structure, SEC fills auth.

**Frozen:** empty `scripts.list` is OK; load/unload `forbidden` until SCRIPT-001 with code `unsupported_capability` only if we mark scripts 1.0 required — they are 1.0 required at GA not at API-001. API-001 may omit script routes until SCRIPT-001 **only if** the registry marks them added in SCRIPT-001. Prefer registry complete with handlers calling Service stubs.

## Required tests

- [ ] Contract tests per route.
- [ ] **Integration:** serve management + proxy, capture flow, `GET /v1/flows` lists it.
- [ ] 401 after SEC; until then document open-dev only on loopback tests.
- [ ] Architecture test: handlers do not call store directly.

## Acceptance criteria

- OpenAPI generated and verify-generated green.
- MCP-001 can bind without renaming IDs.

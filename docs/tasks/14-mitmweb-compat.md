# COMPAT-001: mitmweb Compat Adapter

Status: not-started
Recommended owner: Compat agent
Dependencies: API-001
Exclusive ownership: `internal/control/compat`, `testdata/compat`
Wave: 6 (parallel with MCP-001)

## Goal

Mount mitmweb routes calling `app.Service` only, per `docs/12-mitmweb-compat.md`.

## Design references

- [ ] `docs/12-mitmweb-compat.md`
- [ ] ADR 0008

## Scope

- [ ] All mapped routes.
- [ ] `/options/save` 403.
- [ ] `/processes` 404.
- [ ] Dump JSONL + `X-LabMITM-Dump`.
- [ ] WebSocket `/updates` or document SSE-only fallback — **must implement WS `/updates`** for compat.

## Required tests

- [ ] Route table vs native capability IDs.
- [ ] **Integration:** `GET /flows` after capture.
- [ ] Goldens for list JSON (independent).

## Acceptance criteria

- Compat never implements store logic.

# UI-001: Embedded Operator UI

Status: not-started
Recommended owner: UI agent
Dependencies: API-001, SEC-001
Exclusive ownership: `web/`, `internal/web`
Wave: 8

## Goal

React/TS/Vite Node 22.14.0 SPA: flow list/detail, intercept, status, CA cert download, gated reset. REST only.

## Design references

- [ ] `docs/01-architecture.md` UI
- [ ] `docs/08-security-architecture.md` XSS

## Scope

- [ ] Login bearer/basic → session cookie + CSRF.
- [ ] EventSource `/v1/events/stream` + poll fallback.
- [ ] No parent innerHTML of bodies; sandboxed preview.
- [ ] `make web-test` / `web-build`; CI job `web`.
- [ ] `ui.enabled: false` 404 `/`.

## Required tests

- [ ] SPA fallback.
- [ ] No Relay/Python editor.
- [ ] CSRF required on reset.

## Acceptance criteria

- 1.0 GA blocked without this PR.

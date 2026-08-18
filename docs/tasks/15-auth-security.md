# SEC-001: Auth, CSRF, Audit

Status: not-started
Recommended owner: Security agent
Dependencies: API-001, MCP-001, COMPAT-001
Exclusive ownership: `internal/auth`, CSRF session, audit actor identity
Wave: 7

## Goal

Lab static bearer (≥256-bit), optional Basic mapped to `tokenRef`, CSRF cookie REST-only, 401 on unauthenticated `/v1/flows` and `/flows`.

## Design references

- [ ] `docs/08-security-architecture.md`
- [ ] ADR 0005
- [ ] LabMail SEC-001 behavior

## Scope

- [ ] Token digest compare, file reread on reset/apply.
- [ ] `TestMitmwebScenarioCompat` 401 + auth + capture.
- [ ] MCP bearer-only (reject Basic on `/mcp`).
- [ ] Audit events with actor + transport.

## Required tests

- [ ] **Integration:** 401 then bearer success.
- [ ] Basic maps to same scopes as tokenRef.
- [ ] CSRF mismatch 403.
- [ ] CA key export 403 when disabled.

## Acceptance criteria

- Image-default YAML cannot be unauthenticated remote.

# STA-001: Application Service, Snapshot, Reset

Status: not-started
Recommended owner: Application agent
Dependencies: CFG-001, STORE-001, TLS-001
Exclusive ownership: `internal/app`, `internal/snapshot`, `internal/compiler`, `internal/audit` (ring can start here)
Wave: 5

## Goal

HTTP-less `app.Service` compiling snapshots, reset wiping flows, plan/apply closed ops (even if REST not mounted).

## Design references

- [ ] `docs/04-state-and-configuration.md`
- [ ] `docs/implementation-design.md`
- [ ] ADR 0003

## Scope

- [ ] Compile spec → snapshot; atomic swap.
- [ ] Reset reread YAML + CA files + wipe store; no CA rewrite.
- [ ] Plan/apply operations listed in docs/04.
- [ ] Live listen rebind rejected.
- [ ] Intercept/transform apply live.
- [ ] Wire proxy to snapshot (MAIL-like: sessions re-read snapshot).

## Required tests

- [ ] Reset wipes flows, keeps CA.
- [ ] Apply intercept live with **integration** (need PROXY).
- [ ] Revision conflict.
- [ ] Invalid apply does not swap.

## Acceptance criteria

- Service is ready for REST/MCP adapters with no HTTP types in `internal/app`.

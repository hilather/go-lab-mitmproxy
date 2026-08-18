# ADDON-001: Built-in Transforms

Status: not-started
Recommended owner: Addon agent
Dependencies: FILT-001, STORE-001, PROXY-001
Exclusive ownership: `internal/addon` (not starlark)
Wave: 4

## Goal

Implement built-in addons: anticache, anticomp, modify_headers, modify_body, map_local (allowDir), map_remote, block_list, intercept hold, sticky cookie/auth.

## Design references

- [ ] `docs/22-addon-pipeline.md`
- [ ] `docs/04-state-and-configuration.md` addons
- [ ] `docs/08-security-architecture.md` map_local

## Scope

- [ ] Pipeline hook order.
- [ ] Pattern parsers matching mitmproxy option strings as documented.
- [ ] Intercept sets `flow.Intercepted` and **blocks forward** until resume API exists — provide `addon.Hold` channel API that STA/API will signal. Document the interface in handoff.
- [ ] map_local path escape tests.

## Required tests

- [ ] **Integration:** modify_headers adds a header visible at origin.
- [ ] **Integration:** block_list returns configured status.
- [ ] **Integration:** intercept holds until a test calls Resume on the hold API.
- [ ] map_local refuses `../`.

## Acceptance criteria

- Transforms work without REST (test uses app/addon API).

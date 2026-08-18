# SCRIPT-001: Starlark Scripts

Status: not-started
Recommended owner: Script agent
Dependencies: ADDON-001, STA-001
Exclusive ownership: `internal/starlark`
Wave: 7

## Goal

Load `.star` scripts from allowDir with documented hooks, timeouts, no I/O.

## Design references

- [ ] `docs/22-addon-pipeline.md`
- [ ] ADR 0007

## Scope

- [ ] `go.starlark.net` adapter.
- [ ] Hooks: request/response at minimum; headers/content mutation.
- [ ] 10ms default budget.
- [ ] `.py` still rejected at config (already CFG).

## Required tests

- [ ] **Integration:** script adds response header.
- [ ] Timeout failClosed vs continue.
- [ ] No `open()` / import.

## Acceptance criteria

- scripts.load REST/MCP work after API/MCP exist (rebase). If this PR precedes API, Service methods only.

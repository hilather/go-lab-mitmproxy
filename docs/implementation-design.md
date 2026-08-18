# LabMITM Implementation Design

| Field | Value |
|---|---|
| **Title** | LabMITM Implementation Design |
| **Date** | 2026-08-18 |
| **Status** | Approved for implementation |
| **Audience** | Agents implementing LabMITM |
| **Normative source** | Numbered pack under `docs/` |
| **Target repository** | `https://github.com/hilather/go-lab-mitmproxy` |

This is an **implementation design**, not a rewrite of the design pack. The pack is the source of truth. Where this document restates behavior, it cites pack files.

## Overview

LabMITM is a greenfield Go intercepting-proxy appliance. The worktree starts as a design pack. FND-001 creates the module. Merge order follows `docs/tasks/00-program-board.md`. Parallel lanes follow `docs/tasks/parallelization-plan.md`.

## Import DAG (allowed direction)

```text
cmd/labmitm
  -> internal/app, config, observability, buildinfo, control/*, web, proxy/server

internal/control/{rest,mcp,compat}
  -> capabilities, app, auth, domainerr
  -> NOT proxy, store, tlsint, starlark directly

internal/app
  -> store, snapshot, replay, dump, addon, starlark, filter, domainerr, audit
  -> NOT net/http Server, MCP SDK types

internal/proxy/*
  -> model, store, tlsint, addon, filter, observability
  -> NOT control, web, mcp SDK

internal/tlsint
  -> model, crypto/tls, x509
  -> NOT control

internal/capabilities
  -> model, domainerr
  -> NOT app

internal/model
  -> (stdlib only)
```

CI: `internal/proxy/import_test.go` forbids importing `internal/control` and management HTTP servers.

## Package ownership vs tasks

| Package | First owner task |
|---|---|
| `cmd/labmitm`, Makefile, CI | FND-001 |
| `internal/model`, `internal/config` | CFG-001 |
| `internal/proxy/codec`, `server` HTTP/1 | PROXY-001 |
| `internal/tlsint` | TLS-001 |
| `internal/proxy/h2` | H2-001 |
| `internal/proxy/ws` | WS-001 |
| `internal/store` | STORE-001 |
| `internal/filter` | FILT-001 |
| `internal/addon` built-ins | ADDON-001 |
| `internal/replay`, `internal/dump` | REPLAY-001 |
| `internal/snapshot`, `internal/app` | STA-001 |
| `internal/capabilities`, `control/rest` | API-001 |
| `internal/control/mcp` | MCP-001 |
| `internal/control/compat` | COMPAT-001 |
| `internal/auth` | SEC-001 |
| `internal/observability` | OBS-001 |
| Dockerfile, compose | DEP-001 |
| `internal/starlark` | SCRIPT-001 |
| reverse/socks/upstream extra listeners | MODE-001 |
| `web/`, `internal/web` | UI-001 |
| examples/lab overlay | LAB-001 |
| HTTP/3 | H3-001 |
| privileged modes | PRIV-001 |

Shared files (`internal/model`, capability registry, OpenAPI merge) have a single owner at a time. See parallelization plan.

## Snapshot compiler

STA-001 owns `internal/compiler.Compile`. Domain compile functions:

- `proxy.CompileListeners`
- `tlsint.CompileCA`
- `addon.Compile`
- `store.CompileCaps`

`Compile` returns `*snapshot.Snapshot` swapped atomically.

## PR mapping

See program board. Do not land public REST without MCP in a later PR without a recorded exception: **API-001 may land REST first** only if MCP-001 is the next merge and REST is not advertised as complete. Prefer the same capability freeze: API-001 lands registry + REST; MCP-001 must merge before M2 exit.

**M2 exit (agent-controllable):** STA-001, API-001, MCP-001, `make test-parity` green.

## First files FND-001 must create

`go.mod`, `Makefile` (fail-closed targets), `.github/workflows/ci.yml`, `.github/pull_request_template.md`, `cmd/labmitm` version/help, `internal/buildinfo`, `scripts/checkdocs`, package stubs with `doc.go`.

## Test clocks and listeners

Use `testing/synctest` where available on Go 1.26; otherwise fake clocks in store wait tests. Always bind `127.0.0.1:0`.

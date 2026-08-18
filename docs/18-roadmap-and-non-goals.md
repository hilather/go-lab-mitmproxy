# Roadmap and Non-goals

Status: Proposed
Owners: Product, Architecture
Last reviewed: 2026-08-18 (design pack)

Implementation waves match [docs/tasks/00-program-board.md](tasks/00-program-board.md) and [docs/tasks/parallelization-plan.md](tasks/parallelization-plan.md).

## Phase 0: contracts first

- This pack and ADRs.
- Canonical domain model and capability registry.
- CI and documentation gates (FND-001).

## Phase 1: useful intercepting proxy

- HTTP/1.1 regular + CONNECT.
- TLS intercept + mounted CA.
- Bounded flow store.
- Filters and intercept.

## Phase 2: protocol completeness (1.0)

- HTTP/2, WebSocket.
- reverse / SOCKS5 / upstream.
- Built-in transforms.
- Client/server replay, HAR/JSONL.

## Phase 3: control planes

- REST `/v1` and MCP Streamable HTTP with **full parity**.
- mitmweb compat adapter.
- Auth, audit, plan/apply/reset.

## Phase 4: lab GA

- Starlark scripts.
- Embedded UI.
- Hardened image.
- mcp-integration-lab overlay.
- Fuzz, soak, release notes.

## Phase 5: 1.1 (scheduled tasks, not 1.0 GA)

- HTTP/3 + QUIC (H3-001).
- Privileged modes: transparent, TUN, WireGuard, local (PRIV-001).
- Optional mitmproxy dump **reader**.
- Optional CPython out-of-process addon bridge (new ADR; not in PRIV-001).

## Deferred without a task file

- Console TUI (urwid clone).
- ASGI in-process apps.
- Browser auto-launch.
- LDAP proxyauth.
- DNS reverse mode (LabDNS is the lab DNS).
- Multi-replica flow store.
- OAuth PRM.

Deferred work requires a new task plan and, where architectural, an ADR.

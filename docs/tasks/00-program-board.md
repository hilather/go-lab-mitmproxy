# Program Board

Status: not-started (design pack)
Last reviewed: 2026-08-18

Work packages implement LabMITM 1.0 (and scheduled 1.1 tails). The numbered pack under `docs/` is the source of truth.

## Work packages

| Order | Task | ID | Depends on | Primary output | Wave | Status |
|---:|---|---|---|---|---|---|
| 1 | Repository foundation | FND-001 | None | Go module, CI, Makefile, stub CLI | 0 | not-started |
| 2 | Domain model and YAML | CFG-001 | FND-001 | `labmitm.dev/v1alpha1`, revisions | 1 | not-started |
| 3 | HTTP/1 regular + CONNECT | PROXY-001 | CFG-001 | In-tree HTTP/1 proxy | 2 | not-started |
| 4 | Filter language | FILT-001 | CFG-001 | RE2 filters, testdata table | 2 | not-started |
| 5 | Flow store | STORE-001 | CFG-001 | Caps, wipe, wait | 2 | not-started |
| 6 | TLS interception | TLS-001 | PROXY-001 | CA mount, leaf mint | 3 | not-started |
| 7 | Observability hooks | OBS-001 | PROXY-001 | slog, OpenMetrics, ready | 3 | not-started |
| 8 | HTTP/2 | H2-001 | TLS-001 | h2 intercept + translation | 4 | not-started |
| 9 | WebSocket | WS-001 | PROXY-001, STORE-001 | Upgrade + messages | 4 | not-started |
| 10 | reverse / SOCKS5 / upstream | MODE-001 | TLS-001 | Extra modes | 4 | not-started |
| 11 | Built-in transforms | ADDON-001 | FILT-001, STORE-001, PROXY-001 | map_*, modify_*, block, sticky | 4 | not-started |
| 12 | Application service + snapshot | STA-001 | CFG-001, STORE-001, TLS-001 | `app.Service`, reset | 5 | not-started |
| 13 | Replay + HAR/JSONL | REPLAY-001 | STA-001 | client/server replay, dump | 5 | not-started |
| 14 | REST `/v1` + OpenAPI | API-001 | STA-001 | Native REST, registry | 6 | not-started |
| 15 | MCP + parity | MCP-001 | API-001 | `mitm_*` tools, `make test-parity` | 6 | not-started |
| 16 | mitmweb compat | COMPAT-001 | API-001 | `/flows` shim | 6 | not-started |
| 17 | Auth, CSRF, audit | SEC-001 | API-001, MCP-001, COMPAT-001 | Bearer + optional Basic | 7 | not-started |
| 18 | Starlark scripts | SCRIPT-001 | ADDON-001, STA-001 | `.star` host | 7 | not-started |
| 19 | CLI, image, compose | DEP-001 | OBS-001, API-001 | Hardened image | 7 | not-started |
| 20 | Embedded UI | UI-001 | API-001, SEC-001 | SPA | 8 | not-started |
| 21 | Integration-lab overlay | LAB-001 | COMPAT-001, MCP-001, SEC-001, DEP-001 | examples + BOM | 8 | not-started |
| 22 | CI/docs/release finalization | REL-001 | FND-001; finalize after API+MCP | tag-gate, release-diff | 8 | not-started |
| 23 | GA hardening | GA-001 | PRs 1–22 (except 1.1 tails) | fuzz corpora, soak, notes | 8 | not-started |
| 24 | HTTP/3 + QUIC | H3-001 | H2-001, GA-001 or parallel after H2 | 1.1 protocol | 9 | not-started |
| 25 | Privileged modes | PRIV-001 | DEP-001 + new ADR update | 1.1 transparent/TUN/WG/local | 9 | not-started |

## Waves (parallel)

See [parallelization-plan.md](parallelization-plan.md).

| Wave | Parallel after | Packages |
|---|---|---|
| 0 | — | FND-001 |
| 1 | FND | CFG-001 |
| 2 | CFG | PROXY-001, FILT-001, STORE-001 |
| 3 | PROXY | TLS-001, OBS-001 |
| 4 | TLS + STORE + FILT | H2-001, WS-001, MODE-001, ADDON-001 |
| 5 | STORE + TLS + CFG | STA-001 then REPLAY-001 |
| 6 | STA | API-001 then **MCP-001 ∥ COMPAT-001** (registry owner = API-001) |
| 7 | API+MCP | SEC-001, SCRIPT-001, DEP-001 |
| 8 | SEC+DEP | UI-001, LAB-001, REL-001, GA-001 |
| 9 | 1.1 | H3-001, PRIV-001 (parallel) |

## Milestones

### M0: Contracts compile

FND-001 + CFG-001. CI: format, lint, unit, docs.

### M1: Proxy usable without control plane

PROXY-001, TLS-001, STORE-001, FILT-001. curl through localhost with CA works; flows in memory.

### M2: Agent-controllable

STA-001, API-001, MCP-001, parity green. Plan/apply/reset and `mitm_flows_wait` both transports.

### M3: Lab-complete 1.0

H2, WS, MODE, ADDON, REPLAY, COMPAT, SEC, OBS, DEP, SCRIPT, UI, LAB, GA.

### M4: 1.1 tails

H3-001, PRIV-001. Not required for 1.0 tag.

## Cross-cutting blockers

Stop dependent work when unstable: capability IDs, config schema, domain errors, store generation, MCP protocol pin, CA path layout, filter grammar.

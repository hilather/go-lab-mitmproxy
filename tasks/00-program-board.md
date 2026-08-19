# Program Board

Status: in-progress (PROXY-001 next)
Last reviewed: 2026-08-18 (CFG-001)

Work packages match LabMITM 1.0 design PRs 1–14. The numbered pack under `docs/` is the source of truth.

## Work packages

| Order | Task | ID | Depends on | Primary output | Status |
|---:|---|---|---|---|---|
| 1 | Repository foundation | FND-001 | None | Go module, CI, Makefile, design pack, stub CLI | done |
| 2 | Domain model and fail-closed YAML | CFG-001 | FND-001 | `labmitm.dev/v1alpha1`, reserved-key reject, revisions | done |
| 3 | HTTP/1.1 forward proxy (no TLS intercept) | PROXY-001 | CFG-001 | Absolute-form + CONNECT Hijack, resolve-then-guard | not-started |
| 4 | Lab CA and TLS interception | TLS-001 | PROXY-001 | In-process CA, leaf mint, HTTPS intercept (**M1 gate**) | not-started |
| 5 | Bounded flow store | STORE-001 | PROXY-001, TLS-001 | ULID store, stacked caps, wait, wipe, breakpoint primitives | not-started |
| 6 | Deterministic rewrite and breakpoint | RULES-001 | STORE-001 | First-match rules; no compiler in this PR | not-started |
| 7 | Application service, snapshot, reset | STA-001 | CFG-001, PROXY-001, TLS-001, STORE-001, RULES-001 | `app.Service`, snapshot, plan/apply/reset | not-started |
| 8 | REST `/v1` and OpenAPI | API-001 | PROXY-001, TLS-001, STA-001 | Native REST except UI/session; problem+json; replay | not-started |
| 9 | MCP Streamable HTTP and parity | MCP-001 | API-001 | `mitm_*` tools, `labmitm://` resources, `make test-parity` | not-started |
| 10 | Auth, session, audit identity | SEC-001 | API-001, MCP-001 | Bearer, CSRF session, 401 contract | not-started |
| 11 | Observability | OBS-001 | PROXY-001, API-001 | slog events, hand-rolled OpenMetrics, ready semantics | not-started |
| 12 | CLI completion, image, compose smoke | DEP-001 | PROXY-001, TLS-001, API-001, SEC-001, OBS-001 | Hardened image, compose contract, healthcheck | not-started |
| 13 | Embedded flow-inspector UI | UI-001 | API-001, SEC-001 | React SPA; **required for GA / 1.0** | not-started |
| 14 | GA hardening + lab overlays | GA-001 + SWAP-001 | PRs 1–13 | Fuzz, soak, tag-gate, SWAP overlay BOM | not-started |

## Parallelization

- PR 2 before 3. PR 4 after 3 (**M1 hard gate**). PR 5 after 3+4 (store types can start earlier but merge after `TLSInfo` exists).
- PR 6 after 5. PR 7 after 2+3+4+5+6.
- PR 8 after 3+4+7. PR 9 after 8. PR 10 after 8+9. PR 11 can start once proxy + REST emit hooks.
- PR 12 after 10 (token fixture) and 4 (HTTPS smoke).
- PR 13 must not block proxy/API completeness for an rc, but **1.0 GA requires PR 13**.
- PR 14 last (GA-001 + SWAP-001).

## Milestones

### M0: Contracts compile

- FND-001 and CFG-001 complete.
- ADRs accepted.
- Schema and semantic test fixtures exist.
- CI runs formatting, lint, unit, and docs checks.

### M1: Proxy usable without control plane

- PROXY-001, TLS-001, and STORE-001 complete. PR **4 is required.**
- `curl --proxy` HTTP works; HTTPS intercept works; store bounded.

### M2: Agent-controllable

- RULES-001, STA-001, API-001, MCP-001, and parity tests complete.
- Plan/apply/reset, wait, and parity work through both transports.
- Management never allow-all.

### M3: Secured + observable + packaged

- SEC-001, OBS-001, DEP-001 complete.
- Bearer 401, metrics, hardened image + system CA bundle.

### M4: Deployable release candidate

- UI-001 and GA-001 + SWAP-001 complete.
- Documentation is current.
- Flow-inspector UI ships in 1.0.

### M5: GA

- GA-001 acceptance review passes.
- All required CI must pass on the **tag** commit.
- Residual limitations match [docs/known-limitations.md](../docs/known-limitations.md).

## Frozen product decisions

| ID | Decision |
|---|---|
| D1 | Product LabMITM; repo `go-lab-mitmproxy`; binary `labmitm`; image `ghcr.io/hilather/labmitm`. |
| D5 | No mitmproxy compat surface in 1.0. |
| D6 | Bearer only; no HTTP Basic. |
| D10 | Default binds `127.0.0.1:8888` / `127.0.0.1:8088`. |
| D13 | 1.0 includes the flow-inspector UI; GA is not done without PR 13. |
| D18 | Catalog id `labmitm`; compose-in is a follow-on lab PR. |

## Cross-cutting blockers

The coordinator must stop dependent work when any of these are unstable:

- Canonical IDs and names.
- Configuration schema source.
- Capability registry API.
- Domain error shape.
- Store epoch / generation contract.
- Supported MCP protocol version.
- Dial isolation / CONNECT Hijack contract.

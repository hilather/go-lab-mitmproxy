# Testing Strategy

Status: Proposed normative behavior
Owners: Quality, Proxy, Control Plane
Last reviewed: 2026-08-18 (DEP-001 + UI-001 + SWAP-001 + GA-001)
Related ADRs: 0002, 0004

Every area has regressions. A bug fix starts with a failing test. CI has no optional jobs.

## Layers

| Layer | What | Where |
|---|---|---|
| Unit | config decode/unknown/reserved/byte sizes; store caps/wipe/wait/race; rules first-match; auth scopes; domainerr; OpenMetrics | `internal/*` |
| Proxy protocol | absolute-form GET/POST, hop-by-hop strip, CONNECT Hijack + two GETs, HTTP/2 preface close, SOCKS peek, resolve-then-guard (name→IMDS, name→link-local), `https://` 400, CONNECT without port, WebSocket 101, Expect strip, HTTP_PROXY ignored | `internal/proxy` + `internal/proxytest`; transcripts in `testdata/proxy` |
| TLS intercept | generate CA, files CA, leaf SAN=SNI, client trusting lab CA succeeds, untrusted client fails, upstream verify on/off, ALPN http/1.1 only, non-443 CONNECT tunnels, handshake fail → `tls_handshake` (no blind fallback) | `internal/tlsmitm` + fixture origin in `proxytest` |
| Store | insert/delete/wait/wipe epoch, Pause/Resume/Drop/WaitPaused without HTTP, truncate bodies, stacked caps, spill | `internal/store` |
| REST contract | OpenAPI, auth 401, list/get/delete/wait/resume, problem+json | `internal/control/rest` |
| MCP | 2026-07-28 initialize, tools/list, tool call, origin, bearer | `internal/control/mcp` |
| Parity | every `PARITY_REQUIRED` capability | `make test-parity` |
| Fuzz | YAML decode, HTTP request line/headers, buildinfo | committed `testdata/fuzz` corpora under each package |
| Soak | accept N flows, `Wait`, `Wipe` | `internal/perf` (`-soak-n` / `LABMITM_SOAK_N`; CI default 8; local lab target 100 flows/s for 30s) |
| Race | store insert/delete/wait; snapshot swap; breakpoint resume | `make test-race` |
| Container | non-root, read-only, no caps, healthcheck, proxy smoke | `scripts/test-container.sh` |
| Docs | required files, links, example YAML validates | `make test-docs` |
| Config compat | `testdata/config/valid` + `invalid` | `make test-config-compat` |
| Changelog | user-visible paths require `CHANGELOG.md` | `make test-changelog` |
| Tag gate | notes headings + green required CI on the tag SHA | `.github/workflows/release.yml` |
| UI | SPA fallback, `ui.enabled: false` 404, CSRF header, no exploit/fuzzer/repeater, escaped HTML bodies, CA SPKI on status | `internal/web`, `internal/control/rest/spa_test.go`, `make web-test` |

## Required Make targets

Create when first needed; do not skip. Placeholders must fail closed.

```
make format lint generate verify-generated
make test test-race test-fuzz-smoke
make test-parity test-config-compat test-docs
make test-container security-scan test-changelog
make web-test web-build
```

FND-001 implements `format`, `lint`, `vet`, `build`, `test`, `test-race`, `test-fuzz-smoke`, `test-docs`, and `security-scan`. CFG-001 implements `test-config-compat` (`testdata/config/valid` + `invalid`) and extends `test-fuzz-smoke` with `FuzzDecode`. API-001 implements `generate` / `verify-generated` (`api/capabilities/v1.json`, `api/openapi/v1.json`). MCP-001 implements `test-parity` (`internal/capabilities`, `internal/control/rest`, `internal/control/mcp` plus `testdata/mcp/goldens` and `api/mcp/v1.json`). UI-001 implements `web-test` / `web-build` (Node **22.14.0**, Vite, Vitest; copies `web/dist` into `internal/web/dist`). DEP-001 implements `test-container`. SWAP-001 adds `examples/labmitm.yaml` / MCPJungle / labinfo overlay fixtures and `TestLabOverlayExample`. GA-001 commits fuzz corpora, adds `internal/perf` soak (accept N, wait, wipe), implements `make test-changelog`, and adds Release `tag-gate`.

## Required CI (GA-001)

Jobs: format, lint, unit, race, fuzz-smoke, generated-file, documentation, security-scan, changelog, parity, config-compat, container-test, web. There is no optional or bypassable job. Tag creation is gated by `.github/workflows/release.yml` (`tag-gate`): notes file present, required headings, generated files clean, every required CI job success on the exact tag commit.

Toolchain `GO_VERSION: "1.26.6"`, `GOTOOLCHAIN: local`. golangci-lint `v2.12.2`. govulncheck `v1.1.4`. Actions SHA-pinned.

## Frozen fixtures

- PROXY-001: `testdata/proxy/absolute-https.txt`, `connect-no-port.txt`, `connect-two-gets.txt`, `connect-hijack.txt`, `upgrade-websocket.txt`, `name-imds.txt`, `name-link-local.txt`.
- TLS fixture (TLS-001): `testdata/tls/**` test-only PEMs; generate-mode client that trusts `CertPEM()` succeeds against a fixture origin; untrusted client fails; `CONNECT :80` with intercept on tunnels; `CONNECT :443` to plaintext stores `Error=tls_handshake` with no blind tunnel.
- API-001: REST contract tests (`internal/control/rest`) for auth 401, problem+json, list/get/delete/wait/resume/drop/replay, HMAC cursor stale, `GET /v1/ca` cert-only; `proxy.Replay` HTTP/HTTPS, `HTTP_PROXY` ignored, hairpin rejected.
- MCP-001: `testdata/mcp/goldens/{tools,resources,mutating-tools}.txt`; `internal/control/mcp` initialize/tools/list/tool call/origin/bearer; URI-only `subscriptions/listen` on `labmitm://flows`; `api/mcp/v1.json`.
- SEC-001: `testdata/container/{config.yaml,token}` (bearer, not `dev-loopback-unauth`); REST unauthenticated `GET /v1/flows` is 401; cookie `labmitm_session` + CSRF; token reread on reset/apply keeps sessions on failed secret reread; audit records `actorId`.
- DEP-001: `Dockerfile` (Go 1.26.6-alpine → scratch, UID `65532`, copy `ca-certificates.crt`, no Node stage); `examples/compose.smoke.yaml`; `scripts/test-container.sh` asserts system CA bundle + `SystemCertPool` non-empty + HTTPS intercept fixture + authenticated `/v1/flows`.
- UI-001: `web/` React/TS + Vite (Node **22.14.0**); Vitest login/list/detail/status/reset; no token in web storage; no exploit/fuzzer/repeater; escaped HTML bodies; `ca.spkiSha256` on status; `make web-test` / `make web-build`; CI job `web`.
- SWAP-001: `examples/labmitm.yaml` (published binds, `allowLegacyClients: true`, recommended `allowHosts`); `examples/mcpjungle/servers/labmitm.json` + `groups/integration.json` (append `labmitm`); `examples/labinfo/services-labmitm.yaml` (catalog id `labmitm`); `TestLabOverlayExample`.
- GA-001: committed `testdata/fuzz` corpora for `FuzzInfoString`, `FuzzDecode`, `FuzzReadRequest`; `internal/perf` soak (CI N=8); `scripts/checkchangelog`; `scripts/release-diff`; `.github/workflows/release.yml` `tag-gate`; [docs/releases/v1.0.0-rc.1.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/releases/v1.0.0-rc.1.md).
- STORE-001: `testdata/flows/**` golden captured flows; `internal/store` insert/delete/wait/wipe/epoch, Pause/Resume/Drop/WaitPaused without HTTP, truncate, stacked caps, spill, race; proxy store-full still forwards.
- RULES-001: `internal/rules` first-match, default-off, AND match, no Dial; Resume without HTTP (store only, test-constructed snapshot); proxy delay/drop/status/header/body/breakpoint, stream-vs-mutate `body_skipped`, inner CONNECT drop.
- STA-001: `internal/compiler` (rules engine + CA handle; reuse CA unless `replaceTLS` / reset); `internal/snapshot` atomic swap; `internal/audit` ring + redact (`BEGIN PRIVATE` never logged); `internal/app` Plan/Apply/Reset/Export, reset-wipes-flows, failed reset leaves snapshot+inbox, generate-mode CA rotates on reset, idempotency LRU, `replaceStoreCaps` / `replaceRules` / `replaceTLS` / `replaceAdmission` / `replaceTargets`; proxy loads snapshot per request / CONNECT (in-flight keeps the pin, including response-phase rules); accept-time epoch so reset cannot refill the inbox from an in-flight hop.
- Invalid config fixtures (CFG-001): unknown field, reserved socks/tproxy/publicca/mitmproxy, bare numbers, multi-doc, alias, missing kind, **`upstream.verify` present**.

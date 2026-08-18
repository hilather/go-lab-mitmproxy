# Testing Strategy

Status: Proposed normative behavior
Owners: Quality, Proxy, Control Plane
Last reviewed: 2026-08-18 (STA-001)
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
| Fuzz | YAML decode, HTTP request line/headers, buildinfo | committed `testdata/fuzz` |
| Race | store insert/delete/wait; snapshot swap; breakpoint resume | `make test-race` |
| Container | non-root, read-only, no caps, healthcheck, proxy smoke | `scripts/test-container.sh` |
| Docs | required files, links, example YAML validates | `make test-docs` |
| Config compat | `testdata/config/valid` + `invalid` | `make test-config-compat` |
| Changelog | user-visible paths require `CHANGELOG.md` | `make test-changelog` |
| UI | SPA fallback, `ui.enabled: false` 404, CSRF, no exploit controls | `make web-test` |

## Required Make targets

Create when first needed; do not skip. Placeholders must fail closed.

```
make format lint generate verify-generated
make test test-race test-fuzz-smoke
make test-parity test-config-compat test-docs
make test-container security-scan test-changelog
make web-test web-build
```

FND-001 implements `format`, `lint`, `vet`, `build`, `test`, `test-race`, `test-fuzz-smoke`, `test-docs`, and `security-scan`. CFG-001 implements `test-config-compat` (`testdata/config/valid` + `invalid`) and extends `test-fuzz-smoke` with `FuzzDecode`. `generate`, `verify-generated`, `test-parity`, `test-container`, `test-changelog`, `web-test`, and `web-build` fail closed until their owning PR.

## Required CI (CFG-001)

Jobs: format, lint, unit, documentation, config-compat. There is no optional or bypassable job. Later PRs add race, fuzz-smoke, generated-file, security-scan, container-test, changelog, parity, and web when those targets first exist.

Toolchain `GO_VERSION: "1.26.6"`, `GOTOOLCHAIN: local`. golangci-lint `v2.12.2`. govulncheck `v1.1.4`. Actions SHA-pinned.

## Frozen fixtures

- PROXY-001: `testdata/proxy/absolute-https.txt`, `connect-no-port.txt`, `connect-two-gets.txt`, `connect-hijack.txt`, `upgrade-websocket.txt`, `name-imds.txt`, `name-link-local.txt`.
- TLS fixture (TLS-001): `testdata/tls/**` test-only PEMs; generate-mode client that trusts `CertPEM()` succeeds against a fixture origin; untrusted client fails; `CONNECT :80` with intercept on tunnels; `CONNECT :443` to plaintext stores `Error=tls_handshake` with no blind tunnel. `/v1/flows` assertions wait for API-001.
- STORE-001: `testdata/flows/**` golden captured flows; `internal/store` insert/delete/wait/wipe/epoch, Pause/Resume/Drop/WaitPaused without HTTP, truncate, stacked caps, spill, race; proxy store-full still forwards.
- RULES-001: `internal/rules` first-match, default-off, AND match, no Dial; Resume without HTTP (store only, test-constructed snapshot); proxy delay/drop/status/header/body/breakpoint, stream-vs-mutate `body_skipped`, inner CONNECT drop.
- STA-001: `internal/compiler` (rules engine + CA handle; reuse CA unless `replaceTLS` / reset); `internal/snapshot` atomic swap; `internal/audit` ring + redact (`BEGIN PRIVATE` never logged); `internal/app` Plan/Apply/Reset/Export, reset-wipes-flows, failed reset leaves snapshot+inbox, generate-mode CA rotates on reset, idempotency LRU, `replaceStoreCaps` / `replaceRules` / `replaceTLS` / `replaceAdmission` / `replaceTargets`; proxy loads snapshot per request / CONNECT (in-flight keeps the pin).
- Invalid config fixtures (CFG-001): unknown field, reserved socks/tproxy/publicca/mitmproxy, bare numbers, multi-doc, alias, missing kind, **`upstream.verify` present**.

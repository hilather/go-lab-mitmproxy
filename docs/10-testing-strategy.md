# Testing Strategy

Status: Proposed normative behavior
Owners: Quality, Proxy, Control Plane
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0002, 0004, 0010

Every area has regressions. A bug fix starts with a failing test. **Every new behavior ships with integration tests**, not unit tests alone. CI has no optional jobs (LabDNS rule).

## Layers

| Layer | What | Where |
|---|---|---|
| Unit | config decode/unknown fields; store caps; filter parse; domainerr; auth scopes; OpenMetrics | `internal/*` |
| Proxy protocol | HTTP/1, CONNECT, reverse, SOCKS5, upstream | `internal/proxy` + `internal/proxytest`; `testdata/http` |
| TLS | leaf mint, ignore_hosts splice, mTLS request, wrong clock | `internal/tlsint`; `testdata/tls` |
| HTTP/2 | ALPN, translation to H1, ping keepalive | `internal/proxy/h2` |
| WebSocket | upgrade, messages, kill | `internal/proxy/ws` |
| REST contract | OpenAPI, 401, problem+json | `internal/control/rest` |
| REST integration | listen, bearer, wait, intercept | `internal/control/rest` + `proxytest` |
| Compat | mitmweb paths → app.Service | `internal/control/compat` |
| MCP | 2026-07-28 initialize, tools/list, tool call | `internal/control/mcp` |
| Parity | every `PARITY_REQUIRED` row | `make test-parity` |
| Starlark | sandbox, timeout, hook errors | `internal/starlark` |
| Fuzz | HTTP/1 codec, YAML, filters | committed `testdata/fuzz` |
| Race | store + snapshot + intercept | `make test-race` |
| Container | non-root, read-only, no caps | `scripts/test-container.sh` |
| Docs | links, example YAML | `make test-docs` |
| Config compat | valid/invalid fixtures | `make test-config-compat` |
| Changelog | user-visible paths | `make test-changelog` |
| UI | SPA fallback, CSRF, no innerHTML of bodies | `make web-test` |

## Always-on integration tests

A change is incomplete if it adds proxy, REST, MCP, mode, TLS, addon, or replay behavior without an integration test that:

1. Starts the relevant listener(s) on `127.0.0.1:0`.
2. Drives a real client (`net/http`, `proxytest`, or SOCKS dialer).
3. Asserts wire or store effects.
4. Cleans up with `t.Cleanup`.

Do not skip integration tests with `t.Skip` because “CI has no network”. Origins are local `httptest` servers.

## Required Make targets

Create when first needed; placeholders fail closed.

```
make format lint generate verify-generated
make test test-race test-fuzz-smoke test-integration
make test-parity test-config-compat test-docs
make test-container security-scan test-changelog
```

## Required CI (GA-001)

Jobs: format, lint, unit, race, fuzz-smoke, generated-file, documentation, security-scan, changelog, parity, config-compat, container-test, integration, web.

There is no optional or bypassable job. Tag creation is gated by `.github/workflows/release.yml` (`tag-gate`).

## CI failure hardening

If CI fails on a PR or at the end of a PR chain:

1. Do not merge and do not retry-away the failure.
2. Classify product vs test vs pipeline vs flake.
3. Fix the cause.
4. Add hardening (regression test, timeout, fixture, diagnostic).
5. Write `docs/ci-failure-hardening/YYYY-MM-DD-<slug>.md` from the root template when the failure is non-trivial or flaky.

## Frozen fixtures to add with implementation

- HTTP/1 CONNECT + GET transcripts.
- Filter expression table from [docs/24-filter-language.md](24-filter-language.md).
- Compat goldens for `/flows` JSON shape (independently authored).
- HAR round-trip of a single GET.

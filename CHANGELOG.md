# Changelog

All notable user-visible and operator-visible changes are recorded here. This file is curated; it is not a raw commit log.

## Unreleased

### Added

- Repository foundation: Apache-2.0 license, Go 1.26 module `github.com/hilather/go-lab-mitmproxy`, stub `labmitm` CLI (`version` / `help` only), Makefile, fail-closed CI (format, lint, unit, docs), and the LabMITM 1.0 design pack (`docs/01`–`14` + ADRs 0001–0007).
- Fail-closed `labmitm.dev/v1alpha1` loader (`internal/config`) with `KnownFields(true)`, reserved-name reject, loopback defaults (`127.0.0.1:8888` / `127.0.0.1:8088`), `labmitm validate` / `canonicalize`, published JSON Schema, and `make test-config-compat`.
- HTTP/1.1 forward proxy (`internal/proxy`): absolute-form GET/POST, CONNECT Hijack + raw tunnel, peekListener SOCKS reject, HTTP/2 preface close, resolve-then-guard (name→IMDS / name→link-local), hop-by-hop strip, WebSocket 101 copy, `HTTP_PROXY` ignored. `labmitm serve` binds the proxy; management REST requires a bearer verifier.
- In-process lab CA and HTTPS intercept (`internal/tlsmitm`): `ca.mode` generate (ECDSA P-256) or files, per-host leaf mint (SAN=SNI, LRU 256), ALPN `http/1.1` only, default intercept ports `{443}`. Handshake failure stores `Error=tls_handshake` / `upstream_tls` and does not fall back to a blind tunnel. Private keys are never logged. `GET /v1/ca` returns the PEM certificate only.
- Bounded ULID flow store (`internal/store`): stacked `maxFlows`/`maxBytes`/`maxBodyBytes`, `fullPolicy` reject or evict_oldest, Wait, Wipe/ResetTo epoch, optional spill, Pause/Resume/Drop/WaitPaused breakpoint primitives. Proxy inserts completed flows (with `TLSInfo` when intercept ran). Store-full still forwards. Process shutdown wipes spill.
- Deterministic first-match rules (`internal/rules`, default-off): `delay` / `drop` / `status` / `header` / `body` / `breakpoint`. Match AND of host (exact or `*.suffix`), pathPrefix, pathExact, method, header. Proxy request/response hooks; capture-only tee vs mutating buffer-to-`maxBodyBytes` (fail-closed `body_skipped`). Breakpoint uses `WaitPaused` with a session ctx timeout (continue unmodified on timeout). No compiler, no randomness.
- HTTP-less `app.Service` (`internal/app`): immutable snapshot (`internal/snapshot`), the only compiler (`internal/compiler` — rules engine + CA handle), plan/apply/reset/export, idempotency LRU (256), audit ring + redact (`internal/audit`; never log `BEGIN PRIVATE`). Reset rereads bootstrap YAML, wipes flows, and rotates generate-mode CA. Live apply: `replaceRules` / `replaceTLS` / `replaceAdmission` / `replaceTargets` / `replaceStoreCaps`. Proxy sessions load the snapshot once per request / CONNECT.
- Native REST `/v1` (`internal/control/rest`) over the capability registry (`internal/capabilities`): `application/problem+json`, HMAC list cursors, flow list/get/delete/wait/resume/drop/replay, `GET /v1/ca` cert-only, state plan/apply/reset. Management bind requires bearer with ≥1 usable token (or `--management-listen=off`). Stub UI embed (`internal/web/stub`). Generated `api/capabilities/v1.json` and `api/openapi/v1.json` (`make generate` / `verify-generated`). `proxy.Replay` Dials the origin, ignores `HTTP_PROXY`, and never hairpins the proxy listener.
- Streamable HTTP MCP (`internal/control/mcp`): official SDK v1.7.0, protocol `2026-07-28`, `POST /mcp` (`Stateless: true`), frozen `mitm_*` tools and `labmitm://` resources, URI-only `subscriptions/listen` on `labmitm://flows`, bearer-only (no Basic). `labmitm mcp-stdio --config … --token-file …` (token file required). `allowLegacyClients` default false; listen stays pinned. `make test-parity` and generated `api/mcp/v1.json`.
- Observability (`internal/observability`): hand-rolled OpenMetrics (no `github.com/prometheus/*`), slog JSON events, live/ready probes. Ready = proxy bound + store initialized + (management bound or `--management-listen=off`) + CA compiled if `tls.intercept`. Metrics listen default `127.0.0.1:9090` (empty disables); `publicPath: true` exposes authenticated `GET /v1/metrics`. `labmitm healthcheck --url=http://127.0.0.1:8088/v1/health/ready`. Generated `api/metrics/v1alpha1.json`.
- Lab static bearer (`internal/auth`): SHA-256 digest compare, file refs only, tokens ≥256 bits, no HTTP Basic. REST cookie `labmitm_session` (`HttpOnly`, `SameSite=Lax`, max 64) plus CSRF header `X-LabMITM-CSRF`. Origin allowlist (missing Origin allowed). Unauthenticated `GET /v1/flows` is 401 with `WWW-Authenticate: Bearer realm="labmitm"`. Token files reread on reset/apply; failed reread keeps the live verifier and sessions. Audit records `actorId`. Image fixture `testdata/container/` is `mode: bearer` (not `dev-loopback-unauth`).
- Hardened image (`Dockerfile`): `golang:1.26.6-alpine` → `scratch`, numeric `USER 65532:65532`, no shell, no Node stage, copies `/etc/ssl/certs/ca-certificates.crt` so `x509.SystemCertPool()` is non-empty. Exec-form `HEALTHCHECK` against `GET /v1/health/ready`. `EXPOSE 8888/tcp 8088/tcp`. Compose smoke [`examples/compose.smoke.yaml`](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/compose.smoke.yaml) is read-only, `cap_drop: ALL`, `no-new-privileges`, tmpfs `/tmp`, token mount. `make test-container` / CI `container-test` assert the contract (system CA bundle, HTTPS intercept fixture, authenticated `GET /v1/flows`). `serve` flags: `--proxy-listen`, `--management-listen ADDR|off`, `--shutdown-timeout` (default 5s), `--pid-file`. No `serve --token-file`.

### Changed

- None.

### Fixed

- Intercepted CONNECT treats inner `Upgrade: websocket` + `101` as a bidirectional copy (same 1.0 contract as cleartext). Inner `RoundTrip` failure writes `502` and closes both TLS sides instead of leaving the client waiting.
- Replay hairpin reject covers unspecified proxy binds (`:8888`, `0.0.0.0`, `::`) so a lab-overlay replay cannot Dial the unauthenticated data plane on the listen port.

### Removed or deprecated

- None.

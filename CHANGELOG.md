# Changelog

All notable user-visible and operator-visible changes are recorded here. This file is curated; it is not a raw commit log.

## Unreleased

### Added

- Repository foundation: Apache-2.0 license, Go 1.26 module `github.com/hilather/go-lab-mitmproxy`, stub `labmitm` CLI (`version` / `help` only), Makefile, fail-closed CI (format, lint, unit, docs), and the LabMITM 1.0 design pack (`docs/01`–`14` + ADRs 0001–0007).
- Fail-closed `labmitm.dev/v1alpha1` loader (`internal/config`) with `KnownFields(true)`, reserved-name reject, loopback defaults (`127.0.0.1:8888` / `127.0.0.1:8088`), `labmitm validate` / `canonicalize`, published JSON Schema, and `make test-config-compat`.
- HTTP/1.1 forward proxy (`internal/proxy`): absolute-form GET/POST, CONNECT Hijack + raw tunnel, peekListener SOCKS reject, HTTP/2 preface close, resolve-then-guard (name→IMDS / name→link-local), hop-by-hop strip, WebSocket 101 copy, `HTTP_PROXY` ignored. `labmitm serve` binds the proxy; management stays off until a verifier exists. Capture uses a Null sink. TLS intercept is not implemented (intercept:true still tunnels).

### Changed

- None.

### Fixed

- None.

### Removed or deprecated

- None.

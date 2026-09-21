# Changelog

All notable user-visible and operator-visible changes are recorded here. This file is curated; it is not a raw commit log.

## Unreleased

### Added

- None.

### Changed

- None.

### Fixed

- None.

### Removed or deprecated

- None.

## 1.6.3 - 2026-09-21

Patch of one Unreleased fix after v1.6.2: HTTP/2 unread buffered DATA connection-window credit on stream abort from [PR #78](https://github.com/hilather/go-lab-mitmproxy/pull/78). Catalog stays 31 `/v1` rows. `features.get` stays 11. MCP stays 2026-07-28. No new capability IDs or apply verbs. No fuzzer. Management stays bearer. **D7 stands.** Notes: [docs/releases/v1.6.3.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.6.3/docs/releases/v1.6.3.md). Operator residual: [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.6.3/docs/known-limitations.md).

### Added

- None.

### Changed

- None.

### Fixed

- HTTP/2 `ServeConn` / `OriginConn` now `WINDOW_UPDATE` the connection receive window for DATA that was already buffered when a stream is aborted (silent/hang RST, handler error, origin `RST_STREAM`). Those bytes were counted against the hop-by-hop window and were never `onRead`-credited; without the restore, a later POST on the same intercepted CONNECT could stall until `sessionTimeout`.

### Removed or deprecated

- None.

## 1.6.2 - 2026-09-14

Patch of two Unreleased fixes after v1.6.1: HTTP/2 CONTINUATION `END_STREAM` from [PR #75](https://github.com/hilather/go-lab-mitmproxy/pull/75); HTTP/2 post-RST receive-window credit from [PR #76](https://github.com/hilather/go-lab-mitmproxy/pull/76). Catalog stays 31 `/v1` rows. `features.get` stays 11. MCP stays 2026-07-28. No new capability IDs or apply verbs. No fuzzer. Management stays bearer. **D7 stands.** Notes: [docs/releases/v1.6.2.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.6.2/docs/releases/v1.6.2.md). Operator residual: [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.6.2/docs/known-limitations.md).

### Added

- None.

### Changed

- None.

### Fixed

- HTTP/2 `writeHeaderBlock` now sets `END_STREAM` on the opening `HEADERS` when the HPACK block spans `CONTINUATION` frames. CONTINUATION cannot carry `END_STREAM`, so a GET (or empty-body / trailer) block larger than 16KiB used to leave the stream open and stall the peer until `sessionTimeout`.
- HTTP/2 `ServeConn` now `WINDOW_UPDATE`s the connection receive window for DATA that arrives after RST / forget. Those bytes still count against the hop-by-hop window (RFC 9113 §6.9); without the credit, a later POST on the same intercepted CONNECT could stall until `sessionTimeout`.

### Removed or deprecated

- None.

## 1.6.1 - 2026-09-07

Patch of three Unreleased fixes after v1.6.0: Status `replaceTLS` OCC from [PR #73](https://github.com/hilather/go-lab-mitmproxy/pull/73); origin-h2 early-response upload from [PR #72](https://github.com/hilather/go-lab-mitmproxy/pull/72); HTTP/2 RST window from [PR #74](https://github.com/hilather/go-lab-mitmproxy/pull/74). Catalog stays 31 `/v1` rows. `features.get` stays 11. MCP stays 2026-07-28. No new capability IDs or apply verbs. No fuzzer. Management stays bearer. **D7 stands.** Notes: [docs/releases/v1.6.1.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.6.1/docs/releases/v1.6.1.md). Operator residual: [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.6.1/docs/known-limitations.md).

### Added

- None.

### Changed

- None.

### Fixed

- Status `replaceTLS` now copies hidden `hosts` / `ca` / `upstream` from the same `GET /v1/state` snapshot as `expectedRevision`. The form used to stamp a fresh revision onto a stale full subtree, so a concurrent REST/MCP TLS edit was silently reverted (and generate-mode CA could rotate again) when the operator only changed intercept or ports.
- Origin-h2 intercept no longer truncates a POST/gRPC upload when the origin responds before the client sends `END_STREAM`. `http2x.ServeConn` used to close the inner request body (and drop later DATA) as soon as the stream handler returned, so `OriginConn.writeRequestBody` saw a premature EOF.
- HTTP/2 `outFlow.take` no longer re-opens a forgotten stream after RST. That used to spend the hop-by-hop connection send window on DATA the peer would not credit, so a later stream on the same intercepted CONNECT (or origin-h2 TCP) could stall until `sessionTimeout`.

### Removed or deprecated

- None.

## 1.6.0 - 2026-08-30

Operator SPA live-apply from [PR #70](https://github.com/hilather/go-lab-mitmproxy/pull/70): Status panels for `replaceTLS`, `replaceHTTPAuth`, `replaceRules`, `replaceAdmission`, and nested `replaceCompat`; compact `status.features` `httpAuth` badge plus Reset-required 1.2 flags; ADR [0018](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0018-status-ui-enabled-apply.md) D77 gated `ui.enabled` off-confirm; live intercept chip from `GET /v1/state` `canonical.spec.tls.ports`; Frames tab `drop`/`block` badges. Origin-h2 `OriginConn` DATA + trailer completeness from [PR #69](https://github.com/hilather/go-lab-mitmproxy/pull/69). Catalog stays 31 `/v1` rows. `features.get` stays 11. MCP stays 2026-07-28. No new capability IDs or apply verbs. No fuzzer. Management stays bearer. **D7 stands.** Notes: [docs/releases/v1.6.0.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.6.0/docs/releases/v1.6.0.md). Operator residual: [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.6.0/docs/known-limitations.md).

### Added

- Operator Status live-apply panels for `replaceTLS`, `replaceHTTPAuth` (407 file-ref users), `replaceRules`, `replaceAdmission`, and nested `replaceCompat` `{ compat: { flowREST } }`.
- Status compact `status.features` panel: `httpAuth` badge plus Reset-required 1.2 flags as muted text (one catalog `Reset required` link).
- Status gated `ui.enabled` off-confirm (D77 / ADR 0018). Recovery is REST/MCP.
- Header intercept-ports chip from live `GET /v1/state` `canonical.spec.tls.ports` (not hardcoded `:443 intercept only`).
- Inspector Frames tab badges `drop` / `block` from GET-by-id `frames[].action`.

### Changed

- None.

### Fixed

- Origin h2 (`protocols.http2.origin`) now forwards inner POST/PUT/PATCH/gRPC request DATA. `http2x.OriginConn` treated `ContentLength == 0` as no body, so reconstructed inner streams (h2 often omits content-length) sent HEADERS with END_STREAM and dropped the payload.
- Origin-h2 `http2x.OriginConn` now surfaces trailing HEADERS on `Response.Trailer` (and skips 1xx informational HEADERS). Live intercept with `protocols.http2.origin` forwards gRPC `grpc-status` / other response trailers to the inner client and stores them on the flow instead of dropping the second HEADERS block.

### Removed or deprecated

- None.

## 1.5.0 - 2026-08-29

Operator SPA chrome from [PR #67](https://github.com/hilather/go-lab-mitmproxy/pull/67): split-pane Flows inspector plus leftover Login / Status / Audit / Reset page bodies. Same data-plane as v1.4.0. Catalog stays 31 `/v1` rows. `features.get` stays 11. MCP stays 2026-07-28. No new ADR, apply verb, or metric. No fuzzer. Management stays bearer. **D7 stands.** Notes: [docs/releases/v1.5.0.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.5.0/docs/releases/v1.5.0.md). Operator residual: [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.5.0/docs/known-limitations.md).

### Added

- None.

### Changed

- Operator Flows inspector is a split pane: the live list stays mounted while selection on `/` and `/flows/:id` drives Request / Response / TLS. Completed raw CONNECT is a tunnel-not-decrypt summary (`why not decrypted: port not in tls.ports:[443]`), not empty HTTP panes. Handshake-failure CONNECT stays an error. Dark chrome (IBM Plex OFL-1.1, `#0b0c0e` / `#6ea8d1` / `#c4a35a`) with header chips **live** and **:443 intercept only** (overlay/default copy). Shell restyle: primary nav is a sidenav (Sign out is not new). Status / Audit / Reset / Login page bodies share that chrome; tunnel-not-decrypt stays a flow chip. SSE also refreshes on already-emitted `flow.deleted`. Selection clears to `/` when the selected id is gone. SPA only; no fuzzer/repeater; captured HTML stays escaped text.

### Fixed

- None.

### Removed or deprecated

- None.


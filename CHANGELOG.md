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

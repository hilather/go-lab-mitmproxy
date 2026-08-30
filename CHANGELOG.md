# Changelog

All notable user-visible and operator-visible changes are recorded here. This file is curated; it is not a raw commit log.

## Unreleased

### Added

- None.

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

## 1.4.0 - 2026-08-28

QA knobs from issue #52: block modes (ADR [0014](https://github.com/hilather/go-lab-mitmproxy/blob/v1.4.0/docs/adr/0014-qa-block-modes.md) D69), WebSocket frame rules (ADR [0015](https://github.com/hilather/go-lab-mitmproxy/blob/v1.4.0/docs/adr/0015-websocket-frame-rules.md) D72–D74), throttle (ADR [0016](https://github.com/hilather/go-lab-mitmproxy/blob/v1.4.0/docs/adr/0016-rules-throttle-action.md) D75), and opt-in HTTP 407 (ADR [0017](https://github.com/hilather/go-lab-mitmproxy/blob/v1.4.0/docs/adr/0017-http-proxy-407.md) D76). Catalog stays 31 `/v1` rows. Data-plane 407 is default-off. `inspectFrames` stays Reset-only. Management stays bearer. **D7 stands.** Notes: [docs/releases/v1.4.0.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.4.0/docs/releases/v1.4.0.md). Operator residual: [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.4.0/docs/known-limitations.md).

### Added

- QA block modes as additive `spec.rules` actions ([ADR 0014](https://github.com/hilather/go-lab-mitmproxy/blob/v1.4.0/docs/adr/0014-qa-block-modes.md) D69): `silent` (TCP RST/FIN or HTTP/2 RST_STREAM `CANCEL`), `hang` (required `hang.timeout` 1s–30s, then silent close), and `redirect` (301/302/303/307/308 + required `Location`). Issue #52 `http_status` is the existing `status` type (no alias). Catalog does not grow. Live apply stays `replaceRules`.
- WebSocket frame rules (`phase: websocket`, actions `drop` / `block`) after inspect `101` / inner D63 `:status=200` ([ADR 0015](https://github.com/hilather/go-lab-mitmproxy/blob/v1.4.0/docs/adr/0015-websocket-frame-rules.md) D72–D74). Live path is existing `replaceRules` (and `setFeature rules.enabled` for the master switch). `inspectFrames` stays Reset-only. Catalog stays 31 `/v1` rows. GET-by-id `frames[].action` (`drop` / `block`; omitted when forwarded). `labmitm_rule_hits_total{action="block"}` is a new token; websocket `drop` reuses `{action="drop"}`. `labmitm_ws_frames_total` still counts forwarded frames only.
- `action.type: throttle` with `action.bytesPerSecond` (256 B/s–64 MiB/s, IEC YAML) paces the winning request or response **body** after headers go out. Live via existing `replaceRules`. Catalog stays 31 `/v1` rows. ADR [0016](https://github.com/hilather/go-lab-mitmproxy/blob/v1.4.0/docs/adr/0016-rules-throttle-action.md) (D75).
- Opt-in HTTP proxy 407 on `listeners.proxy` ([ADR 0017](https://github.com/hilather/go-lab-mitmproxy/blob/v1.4.0/docs/adr/0017-http-proxy-407.md) D76). Schema `spec.proxy.httpAuth` (default `enabled: false`). Live apply verb `replaceHTTPAuth` (8th `KnownOp`) via `changes.plan` / `changes.apply`. No new capability ID; catalog stays 31; `features.get` stays 11. Compact `status.features.httpAuth` (K10 reopen). Basic `Proxy-Authenticate` / `Proxy-Authorization` on HTTP/1.1 CONNECT and absolute-form, plus client-facing h2c GET and RFC 9113 CONNECT. 407 via `ResponseWriter` before Hijack with `Content-Length`. Orig-dest, inner intercept, Replay, SOCKS, and h2c Extended CONNECT are out. Overlay stays flags-off. Management stays bearer (D6).

### Changed

- Canonical JSON of any non-empty `rules.items` list grows three empty match keys (`opcode`, `direction`, `payloadContains`). Empty `spec: {}` revision stays stable.
- Response-phase hits on HTTP/1.1 `101` and inner D63 `:status=200` remain `late_skip`. That is no longer the only post-101 rule story: `phase: websocket` may match inspected frames when `inspectFrames` is on.

### Fixed

- D75 HTTP/1.1 response throttle now Flushes after `WriteHeader` so the status line and headers leave net/http bufio immediately. Time-to-first-header is ≪ body time on the default hop (issue [#63](https://github.com/hilather/go-lab-mitmproxy/issues/63)). A 4 KiB body at 1 KiB/s no longer looks like a 4s `delay`.
- Request-phase `silent` / `hang` on an intercept hop now stamp the capture like `innerFlow` (`intercepted: true`, absolute https URL, TLS filled). Wire RST / CANCEL was already correct (issue [#64](https://github.com/hilather/go-lab-mitmproxy/issues/64)).

### Removed or deprecated

- None.

## 1.3.0 - 2026-08-28

Live hop/protocol feature gates (ADR [0013](https://github.com/hilather/go-lab-mitmproxy/blob/v1.3.0/docs/adr/0013-live-protocol-feature-gates.md) D51' + D22 carve). Empty `spec: {}` hop behavior stays 1.0. Native catalog is 31 `/v1` rows. **D7 stands.** Notes: [docs/releases/v1.3.0.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.3.0/docs/releases/v1.3.0.md). Operator residual: [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.3.0/docs/known-limitations.md).

### Added

- Live `setFeature` / `replaceCompat` plan/apply verbs for hop/accept flags: `protocols.http2`, `protocols.websocket`, `protocols.connect`, `protocols.absoluteForm`, `listeners.proxy.acceptSOCKS5`/`acceptSOCKS4`, `compat.flowREST` (enabled via `setFeature`; enabled **and** `pathPrefix` via `replaceCompat`), `rules.enabled` (items unchanged), `ui.enabled`. Apply swaps the snapshot without Reset and without wiping the flow inbox. Plan warns `live_next_connection`. `listeners.originalDestination` is `validation_failed` (edit bootstrap YAML and Reset). `tls.intercept` is `validation_failed` (use `replaceTLS`).
- `features.get` capability (`GET /v1/features`, MCP `mitm_features_list`, resource `labmitm://features`, `mitm.read`). Inserted after `status.get` (`TableRowCount` 31). Returns the 11-row derived hop/protocol catalog. Compact `status.features` five 1.1 booleans stay on `status.get`; the catalog is not nested there. Mutation stays `changes.plan` / `changes.apply`.
- Status page lists the derived feature catalog. Administrators toggle live `setFeature` hop/accept rows via `POST /v1/changes:apply`. `ui.enabled` is read-only on Status (REST/MCP or bootstrap YAML). Reset-only rows link to `/reset`. Viewers see on/off badges only.
- QA bootstrap [examples/qa-websocket-off.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/v1.3.0/examples/qa-websocket-off.yaml) with `protocols.websocket.enabled: false` (fail-closed 403; `labmitm validate`).
- Additive nested hop gates `spec.protocols.websocket.enabled`, `spec.protocols.connect.enabled`, and `spec.protocols.absoluteForm.enabled` (objects, not bare bools; [ADR 0013](https://github.com/hilather/go-lab-mitmproxy/blob/v1.3.0/docs/adr/0013-live-protocol-feature-gates.md) D22 carve). Omitted maps materialize **true** at decode so empty `spec: {}` hop behavior stays 1.0. Canonicalize of empty spec grows those three `enabled: true` objects (plus existing `websocket.inspectFrames: false`). Unknown nested keys (`protocols.http3`, extra gate fields) fail closed. `WebSocketSpec.Enabled` is additive beside `inspectFrames`. Disabled gates 403 `forbidden` before rules/Dial (websocket on both absolute-form and orig-dest HTTP; CONNECT after orig-dest D57 before Hijack; absolute-form only on `serveAbsolute`). Inner HTTP/1.1 websocket 403 keeps the CONNECT. Metric reasons `websocket`, `connect`, `absolute_form`.

### Changed

- Operator residual records the D51' live hop/accept vs Reset bind split. Overlay comments no longer claim catalog stays 30 or that 1.1 hop/accept flags are Reset-only. Compat flow REST enable is live `setFeature` / `replaceCompat`.

### Fixed

- Replay of a captured flow Dials the origin port from the stored URL when `Host` is hostname-only (intercept stores `host=127.0.0.1` and `url=https://127.0.0.1:18443/ok`). Non-default-port HTTP and HTTPS lab origins no longer fail with `upstream request failed` after defaulting to `:80` / `:443`.
- HTTPS `proxy.Replay` now closes the one-shot origin TLS connection after the response body is drained (HTTP/1.1 Transport and 1.2 `NewOriginTransport` h2). Repeated inspector/REST/MCP HTTPS replays no longer leak idle FDs or persistConns per call.
- AGENTS.md and the numbered pack no longer concatenate 1.1/1.2 keep-both leftovers (D48 remainder, live `protocols.http2.origin` replay, SOCKS BIND/UDP/user-pass). `make test-docs` rejects stale “later PR” / duplicate table-row invariants.

### Removed or deprecated

- None.

## 1.2.0 - 2026-08-24

1.2 protocol expansion (ADR [0012](https://github.com/hilather/go-lab-mitmproxy/blob/v1.2.0/docs/adr/0012-protocol-expansion-12.md) D58–D68). Additive `labmitm.dev/v1alpha1` flags, default **off**, bootstrap + **Reset-only** (D51). Empty `spec: {}` remains a 1.0 process. Overlay [examples/labmitm.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/v1.2.0/examples/labmitm.yaml) stays flags-off. Catalog stays 30 `/v1` rows. No new capability IDs. **D7 stands.** Notes: [docs/releases/v1.2.0.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.2.0/docs/releases/v1.2.0.md). Operator residual: [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.2.0/docs/known-limitations.md).

### Added

- SOCKS5/4 BIND behind `listeners.proxy.acceptBind` (D58). Listen on the SOCKS control `LocalAddr()` IP only, never `:0` / `0.0.0.0` / `::`. Unspecified DST (`0.0.0.0:0` / `[::]:0`) is rejected (no Listen). Two-reply raw tunnel (`SOCKS.Command="bind"`, `intercepted=false`). 1.1 `acceptSOCKS5` stays CONNECT-only; flag-off BIND stays `05 07` / SOCKS4 `91`. Hairpin includes live BIND listen ports.
- SOCKS5 UDP ASSOCIATE behind `listeners.proxy.acceptUDPAssociate` (D59). Relay binds the control IP. Unspecified ASSOCIATE DST is legal. First client datagram pins the client UDP source; domain dests LookupIP once then pin; FRAG ≠ 0 dropped; inbound origin floods capped. `acceptSOCKS5` on + UDP off still `05 07`. No orig-dest UDP, no QUIC.
- SOCKS5 username/password behind `listeners.proxy.acceptUserPass` + `userPass.users[]` file refs (D60). Fail-closed RFC 1929 (no NO AUTH fallback). GSSAPI (`0x01`) is never selected. Digests are a snapshot side table, not Canonical, not export. HTTP hop stays unauthenticated (no `Proxy-Authorization`). Management stays bearer (D6).
- Client-facing h2c on PRI leftover when `protocols.http2.clientCleartext` (D61). Flag-off PRI still hard-closes before `gate.acquire`. Flag-on Hijack (no Write) → `http2x.ServeConn` PrefaceTail (do not re-read the 24-byte preface). Regular h2c GET/POST allowed. `:scheme=https` 400. `http.Server` stays HTTP/1.1-only.
- RFC 9113 §8.5 CONNECT on client-facing h2c (D62). Each CONNECT stream is one origin TCP. No HTTP/1.1 200. Handshake failure RSTs (D20); no DATA tunnel. Orig-dest tagged CONNECT stays 400 (D57). Nested inner CONNECT without `:protocol` still RST, **no flow**.
- RFC 8441 Extended CONNECT websocket (`protocols.http2.extendedConnect`, D63). Inner and client-facing `:protocol=websocket` reuse `internal/wsx`. Success is inner `:status=200`. Other `:protocol` values RST, no flow. Illegal h2 `Upgrade: websocket` still RST, no flow.
- Origin HTTP/2 multiplex when `protocols.http2.origin` **and** the inner leaf negotiated `h2` (D64). One CONNECT = one origin TCP. Flag-off keeps D32/D44 h2→h1 transcode. Replay follows the **live** origin flag (off → HTTP/1.1 origin-form with leading-`:` stripped).
- Origin `PUSH_PROMISE` capture-only (`protocols.http2.capturePush`, D65). Inner `EnablePush` stays 0. Promised streams are stored as flows and are **not** forwarded or replayable. Flag-off RSTs the promised id toward origin. Inspector shows parent/promised ids. `labmitm_h2_push_captured_total{result}`.
- Best-effort gRPC protobuf decode (`protocols.http2.grpcDecode`, D66). In-tree length-prefix + protobuf wire tree; no `google.golang.org/protobuf`. Fail-open. grpc-web stays **opaque** (content-type recorded, payload not parsed). REST/MCP `grpc` on GET-by-id; list omits `messages`. Inspector gRPC tab. `labmitm_grpc_decode_total{result}`.
- WebSocket frame inspect (`protocols.websocket.inspectFrames`, D67). Flag-off stays 101 + copy. Flag-on captures RFC 6455 frames under existing store caps (`maxBodyBytes`, 4096 frames, `{ULID}-ws.body` spill). REST/MCP `websocket` on GET-by-id; list omits `frames`. Inspector Frames tab. `labmitm_ws_frames_total{opcode}`.
- ADR [0012](https://github.com/hilather/go-lab-mitmproxy/blob/v1.2.0/docs/adr/0012-protocol-expansion-12.md) records D58–D68.

### Changed

- README and START-HERE: family-style product page with header art, YAML bootstrap walkthrough, and REST/MCP state-loading quick start. Architecture pack, ADRs, and the program board stay linked from the documentation map. GitHub About/topics describe the appliance.

### Fixed

- None.

### Removed or deprecated

- None.

## 1.1.1 - 2026-08-23

Closeout of the tagged 1.1 appliance (overlay lab-readiness, onboarding docs, GA board, D18 wording). Notes: [docs/releases/v1.1.1.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.1.1/docs/releases/v1.1.1.md).

### Added

- None.

### Changed

- Overlay `allowHosts` uses compose DNS names `control` and `taclab` instead of MCP catalog names `labldap` and `labtacacs`.
- README, START-HERE, and docs/14 hygiene for the v1.1.0 tree: collapsed duplicate Status, repaired Build-and-test fence, vendor+local-build compose fragment, and lab rollout resequenced so smoke is after MCP.
- Program board and v1.1.0 notes now record verified tag CI and close GA-001 + SWAP-001; GHCR digest remains unpublished.
- LabMITM is composed in mcp-integration-lab: drop follow-on wording. Lab pin is vendor tag **v1.1.0** + `labmitm:local` (not a GHCR digest). A later appliance tag will align vendored `examples/` with the lab-owned copy; do not bump the lab pin off **v1.1.0** for comments. Catalog id remains **`labmitm`** (D18).

### Fixed

- None.

### Removed or deprecated

- None.

## 1.1.0 - 2026-08-19

First Git tag. Untagged 1.0 appliance: `0ee238b`. Notes: [docs/releases/v1.1.0.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.1.0/docs/releases/v1.1.0.md).

### Added

- Flow-inspector shows 1.1 capture metadata: protocol badge, HTTP/2 stream id, request/response trailers tab, SOCKS dest, and original dest. No attack UX.
- HTTP/2 inner intercept when `protocols.http2.enabled` and the leaf ALPN is `h2`: `innerHTTP` runs `http2x.ServeClient`; `roundTripInnerH2` returns resp/trailers to the codec (D53). One flow per stream with `HTTP2.StreamID`. Rules match `:path`/`:method`/`:authority`. Inner CONNECT / Extended CONNECT / websocket Upgrade is RST `PROTOCOL_ERROR` with no flow (D48). A per-stream 502 does not GOAWAY or close CONNECT. Request-phase `WaitPaused` is outside the origin mutex (D37). Origin ALPN is still `http/1.1` (leading-`:` names stripped). Flag-off / inner `http/1.1` `PRI` stays `http2_inner`. **D7 stands.** Concurrent streams serialize on one HTTP/1.1 origin TCP (`MaxConnsPerHost: 1`; mutex covers `RoundTrip` and full body drain). Replay strips leading-`:` names. h2→h1 request trailers dropped (`labmitm_h2_trailer_dropped_total`).
- Opt-in SOCKS5 CONNECT (optional SOCKS4/4a) multiplexed on `listeners.proxy` when `acceptSOCKS5`/`acceptSOCKS4` are true (D29). NO AUTH only; peeked `0x05`/`0x04` replayed; `gate.acquire` after a valid CONNECT request and before Dial; hairpin and IMDS deny do not Dial; success BND is `0.0.0.0:0` or `::` port 0; intercept uses `serveInterceptConn` (no HTTP 200). Flags off keep 1.0 SOCKS-close. Metric `labmitm_socks_sessions_total`. **D7 stands.**
- Linux original-destination listener (`spec.listeners.originalDestination`, default off): REDIRECT + `SO_ORIGINAL_DST` on a separate bind (empty address → `127.0.0.1:8890`). Dest-IP Dial only (D57); tagged `CONNECT` is 400; origin-form on `:8888` stays 400. Ready bit `OrigDestOff` keeps 1.0 processes ready. Default image USER/caps unchanged; iptables is sidecar/host only. Publishing `8890` is not transparent (D50). Overlay: [examples/compose.originaldest.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/v1.1.0/examples/compose.originaldest.yaml). **D7 stands.**
- LabMITM compat flow REST (mitmproxy-inspired subset): opt-in `GET/DELETE /compat/flows`, `GET/DELETE /compat/flows/{id}`, `POST /compat/flows/{id}/replay`, raw `content/request|response`. After-auth mappers over `internal/app`; native catalog stays 30 `/v1` rows; no new MCP tools. List is a JSON array of the newest 200 with `X-LabMITM-Truncated: true` when more exist. Disabled prefix is `404` `not_found` (SPA cannot swallow it). Same bearer; `Authorization: Basic` is 401 Bearer; cookie mutations require CSRF. Contract: [examples/compat/flow-rest-contract.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.1.0/examples/compat/flow-rest-contract.md). **Not** mitmproxy 11 compatible.
- HTTP/2 codec (`internal/http2x`) over `golang.org/x/net/http2` (ADR [0009](https://github.com/hilather/go-lab-mitmproxy/blob/v1.1.0/docs/adr/0009-http2-via-http2x.md) / D28). Stream API + `ServeClient`; origin pool never Dials (`DialTLS` nil, second open `refuses redial`). Handshake `NextProtos` come from the session snapshot (D46). **D7 stands.**
- 1.1 operator residuals: [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.1.0/docs/known-limitations.md) records HTTP/3 still out, no Python VM, no TPROXY in the appliance, no reverse-proxy, Linux-only orig-dest, compat subset, Reset-only flags, and D50 topologies. **1.0 defaults remain the process defaults.** `make test-container` never requires `NET_ADMIN`; optional `make test-container-originaldest` skips live REDIRECT without it.
- 1.1 foundation (types only): ADRs [0008](https://github.com/hilather/go-lab-mitmproxy/blob/v1.1.0/docs/adr/0008-additive-v1alpha1-11.md)–[0011](https://github.com/hilather/go-lab-mitmproxy/blob/v1.1.0/docs/adr/0011-optional-compat-flow-rest.md). Additive `v1alpha1` fields `acceptSOCKS5`/`acceptSOCKS4`, `listeners.originalDestination`, `protocols.http2`, `compat.flowREST`, `maxConcurrentStreams`, `match.protocol` default **off**. Flow metadata (`via`, `http2.streamId`, `socks`, `originalDest`, trailers) and `GET /v1/status` `features` land so UI can stub later. `capabilities.CompatBindings()` is a side table; catalog stays 30 `/v1` rows. HTTP CONNECT uses extracted `serveInterceptConn`. Flags are Reset-only. **D7 stands.**

### Changed

- Proxy accept mux (D42): Accept never peeks. A per-connection goroutine peeks one byte under `headerTimeout` and SOCKS-closes `0x04`/`0x05` when `acceptSOCKS5`/`acceptSOCKS4` are off. Flags on serve SOCKS CONNECT on the same listener. `chanListener` hands HTTP (including `PRI`) to `http.Server`. Shutdown is stop accept → `chanListener.Close` → `http.Server.Shutdown` → hijack drain.

### Fixed

- SOCKS error replies (`admission`, IMDS/hairpin deny, dial fail) check the write result so golangci-lint `errcheck` stays clean.
- Orig-dest compose overlay skips UID 65532 on OUTPUT REDIRECT (dest-IP Dial must not hairpin to `:8890`) and mounts a bearer bootstrap (`testdata/container/originaldest.yaml`) so `--management-listen=:8088` can bind. Ready `OrigDestOff` is re-read from the live snapshot so Reset-to-enable-without-bind is unready.

### Removed or deprecated

- None.

## 1.0.0-rc.1 (untagged notes)

The HTTP/1.1 appliance that landed on `main` before 1.1. No Git tag was pushed for that tree. Notes: [docs/releases/v1.0.0-rc.1.md](https://github.com/hilather/go-lab-mitmproxy/blob/v1.1.0/docs/releases/v1.0.0-rc.1.md).

### Added

- Repository foundation: Apache-2.0 license, Go 1.26 module `github.com/hilather/go-lab-mitmproxy`, stub `labmitm` CLI (`version` / `help` only), Makefile, fail-closed CI (format, lint, unit, docs), and the LabMITM 1.0 design pack (`docs/01`–`14` + ADRs 0001–0007).
- Fail-closed `labmitm.dev/v1alpha1` loader (`internal/config`) with `KnownFields(true)`, reserved-name reject, loopback defaults (`127.0.0.1:8888` / `127.0.0.1:8088`), `labmitm validate` / `canonicalize`, published JSON Schema, and `make test-config-compat`.
- HTTP/1.1 forward proxy (`internal/proxy`): absolute-form GET/POST, CONNECT Hijack + raw tunnel, peekListener SOCKS reject, HTTP/2 preface close, resolve-then-guard (name→IMDS / name→link-local), hop-by-hop strip, WebSocket 101 copy, `HTTP_PROXY` ignored. `labmitm serve` binds the proxy; management REST requires a bearer verifier.
- In-process lab CA and HTTPS intercept (`internal/tlsmitm`): `ca.mode` generate (ECDSA P-256) or files, per-host leaf mint (SAN=SNI, LRU 256), ALPN `http/1.1` only, default intercept ports `{443}`. Handshake failure stores `Error=tls_handshake` / `upstream_tls` and does not fall back to a blind tunnel. Private keys are never logged. `GET /v1/ca` returns the PEM certificate only.
- Bounded ULID flow store (`internal/store`): stacked `maxFlows`/`maxBytes`/`maxBodyBytes`, `fullPolicy` reject or evict_oldest, Wait, Wipe/ResetTo epoch, optional spill, Pause/Resume/Drop/WaitPaused breakpoint primitives. Proxy inserts completed flows (with `TLSInfo` when intercept ran). Store-full still forwards. Process shutdown wipes spill.
- Deterministic first-match rules (`internal/rules`, default-off): `delay` / `drop` / `status` / `header` / `body` / `breakpoint`. Match AND of host (exact or `*.suffix`), pathPrefix, pathExact, method, header. Proxy request/response hooks; capture-only tee vs mutating buffer-to-`maxBodyBytes` (fail-closed `body_skipped`). Breakpoint uses `WaitPaused` with a session ctx timeout (continue unmodified on timeout). No compiler, no randomness.
- HTTP-less `app.Service` (`internal/app`): immutable snapshot (`internal/snapshot`), the only compiler (`internal/compiler` — rules engine + CA handle), plan/apply/reset/export, idempotency LRU (256), audit ring + redact (`internal/audit`; never log `BEGIN PRIVATE`). Reset rereads bootstrap YAML, wipes flows, and rotates generate-mode CA. Live apply: `replaceRules` / `replaceTLS` / `replaceAdmission` / `replaceTargets` / `replaceStoreCaps`. Proxy sessions load the snapshot once per request / CONNECT.
- Native REST `/v1` (`internal/control/rest`) over the capability registry (`internal/capabilities`): `application/problem+json`, HMAC list cursors, flow list/get/delete/wait/resume/drop/replay, `GET /v1/ca` cert-only, state plan/apply/reset. Management bind requires bearer with ≥1 usable token (or `--management-listen=off`). Generated `api/capabilities/v1.json` and `api/openapi/v1.json` (`make generate` / `verify-generated`). `proxy.Replay` Dials the origin, ignores `HTTP_PROXY`, and never hairpins the proxy listener.
- Streamable HTTP MCP (`internal/control/mcp`): official SDK v1.7.0, protocol `2026-07-28`, `POST /mcp` (`Stateless: true`), frozen `mitm_*` tools and `labmitm://` resources, URI-only `subscriptions/listen` on `labmitm://flows`, bearer-only (no Basic). `labmitm mcp-stdio --config … --token-file …` (token file required). `allowLegacyClients` default false; listen stays pinned. `make test-parity` and generated `api/mcp/v1.json`.
- Observability (`internal/observability`): hand-rolled OpenMetrics (no `github.com/prometheus/*`), slog JSON events, live/ready probes. Ready = proxy bound + store initialized + (management bound or `--management-listen=off`) + CA compiled if `tls.intercept`. Metrics listen default `127.0.0.1:9090` (empty disables); `publicPath: true` exposes authenticated `GET /v1/metrics`. `labmitm healthcheck --url=http://127.0.0.1:8088/v1/health/ready`. Generated `api/metrics/v1alpha1.json`.
- Lab static bearer (`internal/auth`): SHA-256 digest compare, file refs only, tokens ≥256 bits, no HTTP Basic. REST cookie `labmitm_session` (`HttpOnly`, `SameSite=Lax`, max 64) plus CSRF header `X-LabMITM-CSRF`. Origin allowlist (missing Origin allowed). Unauthenticated `GET /v1/flows` is 401 with `WWW-Authenticate: Bearer realm="labmitm"`. Token files reread on reset/apply; failed reread keeps the live verifier and sessions. Audit records `actorId`. Image fixture `testdata/container/` is `mode: bearer` (not `dev-loopback-unauth`).
- Hardened image (`Dockerfile`): `golang:1.26.6-alpine` → `scratch`, numeric `USER 65532:65532`, no shell, no Node stage, copies `/etc/ssl/certs/ca-certificates.crt` so `x509.SystemCertPool()` is non-empty. Exec-form `HEALTHCHECK` against `GET /v1/health/ready`. `EXPOSE 8888/tcp 8088/tcp`. Compose smoke [`examples/compose.smoke.yaml`](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/compose.smoke.yaml) is read-only, `cap_drop: ALL`, `no-new-privileges`, tmpfs `/tmp`, token mount. `make test-container` / CI `container-test` assert the contract (system CA bundle, HTTPS intercept fixture, authenticated `GET /v1/flows`). `serve` flags: `--proxy-listen`, `--management-listen ADDR|off`, `--shutdown-timeout` (default 5s), `--pid-file`. No `serve --token-file`.
- Embedded flow-inspector SPA (`web/` + `internal/web` `go:embed`): React/TS + Vite (Node **22.14.0**), login via bearer (`POST /v1/session`; no Basic), HttpOnly `labmitm_session` + in-memory `X-LabMITM-CSRF`, flow list, flow detail (headers / textual or hex body / TLS / download), status (`ca.spkiSha256` + cert-only CA download), scoped audit, gated reset. Live update is `EventSource` `GET /v1/events/stream` with a 3s `GET /v1/flows` poll fallback. Captured HTML is escaped text. `spec.ui.enabled: false` 404s `/` and keeps REST/MCP. No fuzzer, repeater, exploit, SSL-strip, or Relay. `make web-test` / `make web-build`.
- GA-001: committed fuzz corpora (config, HTTP request line/headers, buildinfo), `internal/perf` soak (accept N flows, Wait, Wipe; CI default N=8; local lab target 100 flows/s for 30s), [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/known-limitations.md), [docs/releases/v1.0.0-rc.1.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/releases/v1.0.0-rc.1.md), `scripts/checkchangelog`, Release workflow `tag-gate`. Tag only on green required CI.
- Integration-lab overlay (SWAP-001): full file-level BOM in [docs/14-integration-lab.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/14-integration-lab.md); `examples/labmitm.yaml` (published binds `:8888`/`:8088`, `allowLegacyClients: true`, recommended `allowHosts`); `examples/mcpjungle/servers/labmitm.json` + `groups/integration.json` (`LABMITM_TOKEN`, append `labmitm`); `examples/labinfo/services-labmitm.yaml` (catalog id `labmitm`). Bind-mounted `labmitm-token` must be **0o644** (UID 65532). Compose-in is a follow-on lab PR (D18). Do not claim the lab already runs LabMITM.

### Changed

- None.

### Fixed

- Intercepted CONNECT treats inner `Upgrade: websocket` + `101` as a bidirectional copy (same 1.0 contract as cleartext). Inner `RoundTrip` failure writes `502` and closes both TLS sides instead of leaving the client waiting.
- Replay hairpin reject covers unspecified proxy binds (`:8888`, `0.0.0.0`, `::`) so a lab-overlay replay cannot Dial the unauthenticated data plane on the listen port.
- Flow body downloads (`GET /v1/flows/{id}/request|response`) no longer reflect captured `Content-Type`. They are `application/octet-stream` with `Content-Disposition: attachment` and `Content-Security-Policy: default-src 'none'`. The inspector fetches a blob instead of navigating the operator document to captured HTML.

### Removed or deprecated

- None.

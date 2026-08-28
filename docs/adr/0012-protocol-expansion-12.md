# ADR 0012: 1.2 protocol expansion (D58–D68)

Status: Accepted
Date: 2026-08-23
Decisions: D58, D59, D60, D61, D62, D63, D64, D65, D66, D67, D68

## Context

LabMITM 1.1 shipped opt-in SOCKS5/4 **CONNECT** (NO AUTH), HTTP/2 on the **intercepted inner** hop transcoded onto one HTTP/1.1 origin TCP, and WebSocket as `101` plus bidirectional copy. BIND/UDP, SOCKS user/pass, frame inspect, client-facing h2c, HTTP/2 CONNECT to the proxy, Extended CONNECT (including websocket-on-h2), origin `h2`, `PUSH_PROMISE` capture, and gRPC protobuf decode are out of 1.1.

Those residuals are architectural invariants, not TODOs: [ADR 0009](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0009-http2-via-http2x.md) **D26** (client-facing hop HTTP/1.1-only), **D48** (inner CONNECT / Extended CONNECT RST), **D32** (origin locked to HTTP/1.1 transcode); [ADR 0010](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0010-socks-and-original-destination.md) **D29** (CONNECT + NO AUTH only); [docs/01-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/01-architecture.md) **D17** (cited by ADR 0010 D29; **not** an ADR 0002 decision) “data plane is unauthenticated.”

This ADR is the 1.2-class expansion. It is **not** a 1.1 flag tweak. Empty `spec: {}` remains a 1.0 process (HTTP/1.1 on every hop, SOCKS peek-close, `PRI * HTTP/2.0` hard close, 101-copy). New public fields stay additive `labmitm.dev/v1alpha1`, default **off**, bootstrap + **Reset-only** (D51). Overlay [`examples/labmitm.yaml`](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/labmitm.yaml) keeps every new flag off.

The in-tree proxy stands (D7). No `elazarl/goproxy`, `google/martian`, or Python mitmproxy. Production Dial idents stay in `internal/proxy` only. `internal/http2x` remains a codec. REST/MCP stay adapters over `internal/app`; no new capability IDs; `catalog()` stays 30 `/v1` rows.

This ADR supersedes:

- ADR 0009 **D26 hop list** (client-facing may be h2c when `clientCleartext`).
- ADR 0009 **D48 Extended CONNECT / `:protocol=websocket` sentence only**. Nested inner CONNECT without `:protocol` still RST, **no flow**. Illegal h2 `Upgrade: websocket` still RST, **no flow**.
- ADR 0009 **D32 origin lock** (origin ALPN may include `h2` when `origin` and the inner leaf negotiated `h2`).
- ADR 0010 **D29 CONNECT-only / NO AUTH-only** for BIND, UDP ASSOCIATE, and username/password.
- Architecture **D17** “data plane is unauthenticated” sentence **for SOCKS only**.

**Does not supersede:** D7, D8 (1.0 default), D16, D17 remainder (no `Proxy-Authorization`; HTTP hop unauthenticated), D6 (no management Basic), D19, D20, D21, D27, D28, D34, D41, D42, D44 (h2→h1 path), D48 remainder, D51, D53.

## Decision

**D58 — SOCKS BIND is a separate Reset-only flag.** SOCKS5 BIND (and SOCKS4 BIND when `acceptSOCKS4`) requires `listeners.proxy.acceptBind` (default false). A 1.1 `acceptSOCKS5` CONNECT-only config must not grow ephemeral listeners on upgrade. Listen on the SOCKS control `LocalAddr()` IP, never `0.0.0.0`/`::`. Unspecified DST (`0.0.0.0:0` / `[::]:0`) is rejected. BIND is always a raw tunnel (`intercepted=false`). Legal name `acceptBind` (not `socks*`; reserved after normalize).

**D59 — SOCKS5 UDP ASSOCIATE is a separate Reset-only flag.** `listeners.proxy.acceptUDPAssociate` (default false). Datagram relay is a different threat than TCP CONNECT. `acceptUDPAssociate` → `acceptudpassociate` after normalize; `socks*` stays reserved.

**D60 — SOCKS5 username/password is opt-in; GSSAPI remains a non-goal.** Flag `acceptUserPass` plus `userPass.users[]` file refs. **D17 is superseded only for SOCKS:** the HTTP hop stays unauthenticated (no `Proxy-Authorization`); management stays bearer (D6). Fail-closed: if `acceptUserPass` is true, NO AUTH (`0x00`) is **not** selected even if offered. Credentials are a snapshot side table `SOCKSUsers` (not Canonical, not export). Digest = `SHA-256(len||username||len||password)` (uint8 lengths, RFC 1929 1–255). Copy `Previous.SOCKSUsers` when `Previous != nil`; load files only on Start/Reset. Do not reuse `Verifier` or management token files. Do not key reload off TLS equality. GSSAPI (method `0x01`) stays out.

**D61 — Client-facing h2c on PRI when `protocols.http2.clientCleartext` (default false).** Flag-off keeps the 1.0/1.1 PRI hard close. This supersedes **D26’s hop list only**. PRI leftover: `http.Server` already consumed `PRI * HTTP/2.0\r\n\r\n`; leftover is `SM\r\n\r\n` plus SETTINGS in the `bufio.ReadWriter`. `ServeConn` must **not** re-read the 24-byte preface. Regular h2c GET/POST **allowed** (absolute-form). `:scheme=https` 400. No stdlib unencrypted HTTP/2 on `http.Server`. Peek stays 1 byte (D49); PRI detection stays in the Handler.

**D62 — HTTP/2 CONNECT to the proxy is valid only on a client-facing h2c session.** RFC 9113 §8.5. Each CONNECT **stream** is one upstream TCP (D27 per-stream). Nested inner CONNECT **without** `:protocol` stays RST (narrow D48 remainder), **no flow**. Handshake failure closes the stream — no DATA tunnel (D20). Never return the conn to `http.Server` (D19).

**D63 — Extended CONNECT (RFC 8441) when `protocols.http2.extendedConnect`.** Inner and client-facing `:protocol=websocket` use the same `internal/wsx` frame path. Other `:protocol` values RST, **no flow**. Illegal h2 `Upgrade: websocket` still RST, **no flow**. Success to the inner client is HEADERS `:status=200` (not 101).

**D64 — Origin ALPN may include `h2` only when `protocols.http2.origin` and the inner leaf negotiated `h2`.** Still **one CONNECT = one origin TCP**. Flag-off keeps D32/D44 transcode. Inner `http/1.1` sessions never offer origin `h2`. A second origin TCP per stream is forbidden. `DialTLSContext` stays the refuse-redial stub.

**D65 — `PUSH_PROMISE` is capture-only on the origin hop** (`protocols.http2.capturePush`). Inner SETTINGS `EnablePush` stays 0. Promised streams are stored as flows, not forwarded. Replay of a pushed flow is rejected.

**D66 — gRPC decode is best-effort, default-off** (`protocols.http2.grpcDecode`). In-tree length-prefix + protobuf wire tree. **No new module dep.** Unknown/malformed → keep raw DATA. **grpc-web is opaque** (record content-type, do not parse). Fail-open: the hop still forwards.

**D67 — WebSocket frame inspect is default-off** `protocols.websocket.inspectFrames`. Frames count toward existing stacked store caps (`maxBodyBytes` / `maxBytes` / spill). No database. Flag-off remains 101 + bidirectional copy.

**D68 — UDP sockets, BIND listens, and `ListenPacket` live only in `internal/proxy`.** Every UDP dest is resolve-then-guard; no second resolve; same metadata/link-local deny. Hairpin (D34) includes every live BIND/UDP associate port. **UDP first datagram pins the client UDP source**; later packets from any other source are dropped. The RFC ASSOCIATE request UDP port is not a second allowed source.

**D7, D16, D19, D20, D21, D28, D41, D42, D51 stand.** New flags are Reset-only (D51). No live `replaceProtocols` / `replaceProxyAccept`.

### Frozen operator names (K10)

`GET /v1/status` `features` keeps the 1.1 keys. Additive booleans (default false); REST and MCP private `statusFeaturesJSON` copies stay in lockstep:

`http2ClientCleartext`, `http2Origin`, `http2ExtendedConnect`, `http2CapturePush`, `http2GRPCDecode`, `inspectWebSocketFrames`, `acceptBind`, `acceptUDPAssociate`, `acceptUserPass`.

[ADR 0017](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0017-http-proxy-407.md) **reopens K10** for one additive compact key: `httpAuth` (from `spec.proxy.httpAuth.enabled`). That reopen is 0017, not this ADR.

No new `capabilities.catalog()` rows. Catalog stays 30 `/v1` rows. Legal camelCase only; after normalize, keys must not match reserved `socks*` / `tproxy` / `exploit` / …. That is why there is no `socksBind` / `socksUserPass` field.

### Frozen open questions

Re-open only with a new ADR:

1. **BIND flag** — `acceptBind` default false. Not riding `acceptSOCKS5`.
2. **grpc-web** — opaque. Record content-type; do not parse the 5-byte prefix.
3. **`features` JSON names** — the K10 list above. Existing 1.1 keys unchanged.
4. **Client-facing h2c regular GET/POST** — allowed (absolute-form equivalent on `:8888`). `:scheme=https` stays 400. Not CONNECT-only. Orig-dest tagged h2c CONNECT stays 400 (D57).
5. **UDP client endpoint** — first-datagram pin. Later packets from any other source are dropped.

### Replay (K9)

Replay uses the **live** snapshot, not capture-time flags. D21 stands: `Transport.RoundTrip` / origin Framer, no `http.Client`, `isHairpin`, no second resolve. HTTPS replay closes the one-shot origin TLS conn after the response body is drained (HTTP/1.1 Transport and `NewOriginTransport` h2). `Protocol=websocket`, `Method=CONNECT`, SOCKS BIND/UDP metadata-only, and `HTTP2.Pushed=true` remain rejected. Intercepted SOCKS inner GET/POST remain replayable. gRPC decoded tree is not re-encoded (raw captured body). Live origin flag off keeps 1.1 origin-form replay (leading-`:` stripped). Live origin flag on may send HTTP/2 to origin.

## Consequences

- No proxy behavior in this change. Schema, codec, and listener work land in later PRs behind the flags.
- Empty `spec: {}` remains a 1.0 process. 1.1 `acceptSOCKS5` remains CONNECT-only until `acceptBind` is set.
- Overlay lab YAML stays flags-off.
- Catalog stays 30 `/v1` rows. No new capability IDs. Compat flow REST does not grow a frames array.
- D7 is **not** superseded. Third-party MITM/proxy libraries stay forbidden.
- This is one umbrella ADR. D-numbers stay D58–D68 if a later review splits SOCKS / frames / h2c into 0013/0014.

## Alternatives considered

- Enable BIND/UDP whenever `acceptSOCKS5` is true: rejected (D58, D59). Would turn 1.1 CONNECT-only labs into ephemeral listeners / UDP relays on upgrade.
- Third-party SOCKS or MITM library: rejected (D7).
- Stdlib `http.Server` unencrypted HTTP/2 for h2c: rejected (D19). CONNECT must Hijack and never return to `http.Server`.
- Third-party WebSocket library: rejected. Frame codec in-tree (`internal/wsx`); no Dial, no MITM library.
- Origin HTTP/2 via a second TCP per inner stream: rejected (D27). Multiplex on the already-dialed origin conn.
- `google.golang.org/protobuf` + proto registry: rejected for 1.2 (D66). In-tree wire tree; no new module.
- Always-on frame inspect: rejected (D67). Changes the 1.0 101-copy resource profile.
- GSSAPI “best-effort” without Kerberos: rejected. A stub that selects `0x01` then fails is worse than never selecting it.
- SOCKS user-pass as HTTP Basic / `Proxy-Authorization`: rejected (D6, D17 remainder).

## Review triggers

Review when HTTP/3 / QUIC, TPROXY, GSSAPI, client-facing TLS on `listeners.proxy`, forwarding origin `PUSH_PROMISE` to the inner client, a generic gRPC / protobuf framework, or live-apply of 1.2 flags is proposed (each needs a new ADR). Review if the D48 remainder (nested inner CONNECT without `:protocol`) is reconsidered.

HTTP `Proxy-Authorization` landed as [ADR 0017](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0017-http-proxy-407.md) / D76 (live `replaceHTTPAuth`; K10 additively names `httpAuth`). This ADR’s D17 remainder still describes the default-off empty-spec hop; 0017 supersedes it only when `httpAuth.enabled`.

## Notes (D51')

[ADR 0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md) replaces **D51** with **D51'** for hop/accept vs bind. **1.2 flags in this ADR remain Reset-only** (`acceptBind`, `acceptUDPAssociate`, `acceptUserPass`, `protocols.http2.clientCleartext` / `origin` / `extendedConnect` / `capturePush` / `grpcDecode`, `protocols.websocket.inspectFrames`). Live apply of 1.2 flags still needs a new ADR.

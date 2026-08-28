# Known limitations (1.2 residuals; 1.0 defaults)

Honest residual for the LabMITM 1.2 protocol expansion series (stacked PRs 1–13; ADR 0012 D58–D68: SOCKS BIND / UDP ASSOCIATE / username-password, WebSocket frame inspect, client-facing h2c, RFC 9113 CONNECT, Extended CONNECT, origin `h2`, gRPC decode, `PUSH_PROMISE` capture). These are not defects hidden from the notes. They are product bounds, default-off flags, or work that is **not** claimed here.

Last reviewed: 2026-08-28 (features.get listing)

This file is the operator-facing residual list. The numbered pack still wins on conflict: [docs/01-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/01-architecture.md#residual-limitations). Current tag notes: [docs/releases/v1.2.0.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/releases/v1.2.0.md). Untagged 1.0 notes remain [docs/releases/v1.0.0-rc.1.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/releases/v1.0.0-rc.1.md) (HTTP/1.1-only hops, no SOCKS, no orig-dest, no compat path). ADR [0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) records D58–D68. ADR [0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md) records **D51'** (live hop/accept vs Reset bind) and the **D22 carve** (1.0-preserving hop gates default on).

LabMITM is a **laboratory intercepting proxy**. It is **not a public** edge proxy and not an attack framework. It never wraps, vendors, or execs Python mitmproxy. **D7 stands.** Overlay YAML ([examples/labmitm.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/labmitm.yaml)) keeps every 1.1 and 1.2 flag **off**. Catalog is 31 `/v1` rows including `features.get`.

## 1.0 defaults remain the process defaults

1.1 **opt-in** and 1.2 fields are additive `labmitm.dev/v1alpha1` and **default off** (D22). Gates whose zero value would change 1.0 hop behavior (`protocols.websocket` / `connect` / `absoluteForm`) default **on** at decode (D22 carve, [ADR 0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md)). `ui.enabled` remains the 1.0 D13 true default. An empty `spec: {}` is still a 1.0 process: HTTP/1.1 on every hop, SOCKS peek-close, `PRI * HTTP/2.0` hard close, 101-copy, no original-destination listener, no `/compat` routes, loopback binds.

| Surface | Default (1.0) | Opt-in (Reset-only except as noted) |
|---|---|---|
| Client-facing proxy hop (`:8888`) | HTTP/1.1 absolute-form + CONNECT. `PRI * HTTP/2.0` hard close | 1.2 `protocols.http2.clientCleartext` (h2c on PRI leftover). Flag-off PRI still hard close |
| Inner + origin ALPN | `http/1.1` only. Inner `PRI` → `Error=http2_inner` | 1.1 `protocols.http2.enabled` (inner). 1.2 `origin` may offer origin `h2` only when the inner leaf negotiated `h2` |
| SOCKS on `listeners.proxy` | Peek `0x04`/`0x05` → close | 1.1 `acceptSOCKS5` / `acceptSOCKS4` = **CONNECT only**. 1.2 `acceptBind` / `acceptUDPAssociate` / `acceptUserPass` are **separate** flags |
| WebSocket | `101` + bidirectional copy (`websocket.enabled` defaults **on**, D22 carve). Gate-off is `403` `forbidden` before rules/Dial (`reason=websocket`). Inner HTTP/1.1 403 keeps CONNECT | 1.2 `protocols.websocket.inspectFrames` (Reset-only). 1.2 `extendedConnect` / h2c `:protocol=websocket` are **not** this 1.0 gate |
| Extended CONNECT | Inner CONNECT / `:protocol` RST, **no flow** | 1.2 `protocols.http2.extendedConnect` (`:protocol=websocket` only) |
| `PUSH_PROMISE` | Inner `EnablePush=0`; flag-off RST toward origin | 1.2 `protocols.http2.capturePush` (capture-only, not forwarded) |
| gRPC | HTTP/2 headers + DATA | 1.2 `protocols.http2.grpcDecode` (best-effort; grpc-web opaque) |
| Original destination | Unbound. Ready bit `OrigDestOff` | 1.1 `listeners.originalDestination.enabled` (Linux REDIRECT) |
| Compat flow REST | Effective prefix `404` `not_found` | 1.1 `compat.flowREST.enabled` (default prefix `/compat`) |
| Standalone binds | `127.0.0.1:8888` / `127.0.0.1:8088` (D10) | Empty orig-dest address → `127.0.0.1:8890` when enabled |
| Image | `USER 65532:65532`, `cap_drop: ALL`, no `NET_ADMIN` | **Unchanged.** iptables is sidecar/host only |

**D51' live hop/accept vs Reset bind** ([ADR 0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md)). Hop/accept flags the running proxy honors (`protocols.http2.enabled`, `protocols.websocket` / `connect` / `absoluteForm`, `acceptSOCKS5`/`acceptSOCKS4`, `compat.flowREST`, `rules.enabled`, `ui.enabled`) are live-applyable via `setFeature` (and `replaceCompat` for the compat subtree, including `pathPrefix`) without Reset or wiping flows. Disabled hop gates 403 `forbidden` before rules/Dial. Orig-dest **bind**, listener **addresses**, management TLS files, and `metrics.listen` stay Reset-only. 1.2 nested flags stay Reset-only. There is no `replaceProtocols` / `replaceProxyAccept`. `maxConcurrentStreams` rides `replaceAdmission` (new TCP sessions only). `features.get` lists the 11-row catalog (`GET /v1/features`, `mitm_features_list`, `labmitm://features`); mutation stays `changes.plan` / `changes.apply`. Compact `status.features` five 1.1 booleans stay on `status.get`.

Legal YAML names are camelCase (`acceptSOCKS5`, `acceptBind`, `acceptUDPAssociate`, `acceptUserPass`, `originalDestination`, `protocols.http2`, `protocols.websocket`, `compat.flowREST`). Reserved keys (`socks*`, `tproxy`, `transparent`, `mitmproxy*`, `reverseproxy`, …) stay forbidden. `accept-socks5` / `accept-bind` fail KnownFields.

**1.1 `acceptSOCKS5` stays CONNECT-only** unless `acceptBind` / `acceptUDPAssociate` / `acceptUserPass` are also set. A 1.1 CONNECT-only config does not grow BIND listens, UDP sockets, or a user-pass handshake on upgrade.

## 1.2 series residual versus what is not tagged

The 1.2 protocol expansion (ADR 0012 D58–D68) is the claimed product on this tag. What is **not** claimed:

| 1.2 series | Not this product |
|---|---|
| Opt-in HTTP/2 inner+origin (h2c, Extended CONNECT, origin `h2`, PUSH capture, gRPC decode), SOCKS5/4 CONNECT + BIND/UDP/user-pass, Linux orig-dest REDIRECT, compat flow REST, inspector Frames / push metadata | HTTP/3 / QUIC; TPROXY appliance; reverse-proxy; Python mitmproxy; GSSAPI |
| First-party flow-inspector SPA | mitmproxy mitmweb / Python addon UI |
| Overlay examples in this repo (**flags off**) | mcp-integration-lab compose pin lives in that repo (vendor **v1.1.0** + `labmitm:local`; not a GHCR digest) |

**Catalog id is `labmitm` (D18).** Lab compose-in is vendor tag **v1.1.0** + image `labmitm:local`. A later appliance tag will align vendored `examples/` with the lab-owned copy; do not bump the lab pin off **v1.1.0** for comments.

## Still out of 1.2 (non-goals)

- **HTTP/3 / QUIC.** No QUIC listener, no `h3` ALPN, no datagrams.
- **GSSAPI** (SOCKS method `0x01` / RFC 1961). Never selected. If that is the only method offered, the reply is `0xFF`.
- **Nested inner CONNECT without `:protocol`.** Still RST `PROTOCOL_ERROR`, **no flow** (D48 remainder). Illegal h2 `Upgrade: websocket` still RST, no flow. Other `:protocol` values RST, no flow.
- **grpc-web envelope.** `application/grpc-web` / `application/grpc-web+proto` record the content-type header; payload stays **opaque**. No 5-byte grpc-web prefix parse.
- **Unspecified BIND DST.** `0.0.0.0:0` / `[::]:0` / empty is rejected (no Listen). RFC 1928 allows unknown DST; 1.2 does not — FTP clients must name the expected peer.
- **TPROXY in the appliance.** `tproxy` stays reserved. No `IP_TRANSPARENT`, no `CAP_NET_ADMIN` on the default image. Transparent intercept is Linux **REDIRECT + `SO_ORIGINAL_DST`** on a separate listener (sidecar/host iptables). UDP ASSOCIATE is not orig-dest transparent UDP.
- **Python VM / wrap.** No addon VM, no mitmweb SPA clone, no mitmproxy `.mitm` dumpfile, no CLI flag clone (`--mode`, `--set`, `--listen-host`). Do not wrap, vendor, or exec Python `mitmproxy` / `mitmdump` / `mitmweb`.
- **Reverse-proxy / ingress.** `reverseproxy` stays reserved. LabMITM is a forward proxy (+ optional orig-dest).
- **Windows / macOS original-destination.** Linux-only (`SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST`). Non-linux `enabled: true` fails `Start` closed and binds nothing.
- **Compat subset, not mitmproxy 11.** List/get/delete/clear/replay + raw content only. Out: mitmweb, dumpfile, CLI flags, addon, HTTP Basic, PUT mutate, UUID ids, filter DSL, HAR export. Headline: “LabMITM compat flow REST (mitmproxy-inspired subset).” Contract: [examples/compat/flow-rest-contract.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/compat/flow-rest-contract.md).
- **HTTP Basic on management (D6).** `Authorization: Basic` is 401 Bearer.
- **HTTP `Proxy-Authorization`.** SOCKS user-pass does not add it. The HTTP hop stays unauthenticated (D17 remainder).
- **Client-facing TLS on `listeners.proxy`** (HTTPS proxy). h2c is cleartext PRI only; inner `h2` remains the intercepted leaf ALPN path.
- **Forwarding origin `PUSH_PROMISE` to the inner client.** Capture-only; inner `EnablePush` stays 0.
- **Public CA, SSL-strip, exploit/fuzzer UX, chaos engine, durable flow-directory, multi-replica store.**
- **Docker `-p 8890:8890` as “transparent mode.”** Publishing `8890` is not transparent (D50).
- **`labmitm send` / live apply of 1.2 nested flags / HAR export.** 1.1 hop/accept live apply is the accepted D51' path ([ADR 0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md)) for http2/websocket/connect/absoluteForm/SOCKS/compat/rules/ui. Orig-dest bind stays Reset-only.

## Original-destination topologies (D50)

Supported **only**:

1. **Shared netns:** SUT uses `network_mode: service:labmitm`. A sidecar (not the appliance) has `CAP_NET_ADMIN` and installs iptables/nft REDIRECT. labmitm stays UID `65532`, `cap_drop: ALL`.
2. **Host network:** labmitm `--network host` (still UID 65532) + **host** iptables REDIRECT to `127.0.0.1:8890`.

**Not supported:** Docker published-port DNAT to `:8890`. `SO_ORIGINAL_DST` then sees the container dest (often `:8890`) → direct-connect close or hairpin.

Overlay: [examples/compose.originaldest.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/compose.originaldest.yaml). Do not redirect 8088, 8888, 8890, or 9090. REDIRECT must skip UID `65532` on OUTPUT or dest-IP Dial hairpins back to `:8890`. `make test-container` never requires `NET_ADMIN`.

## HTTP/2 residuals (when enabled)

- Flag-off client-facing `:8888` / orig-dest cleartext stay HTTP/1.1; `PRI * HTTP/2.0` is a hard close **before** `gate.acquire`.
- `clientCleartext` enables h2c on PRI leftover (`http2x.ServeConn` PrefaceTail; do not re-read the 24-byte preface from the raw conn). Regular h2c GET/POST is allowed (absolute-form). `:scheme=https` is 400. RFC 9113 §8.5 CONNECT is valid only on a client-facing h2c session; each CONNECT stream is one origin TCP. That 1.2 h2c CONNECT is **not** `protocols.connect` (HTTP/1.1 CONNECT on `:8888`). Orig-dest tagged CONNECT stays 400 (D57). `extendedConnect` `:protocol=websocket` (inner or h2c) is **not** `protocols.websocket` (HTTP/1.1 Upgrade). Those nested flags stay Reset-only.
- Nested inner CONNECT without `:protocol` still RST, **no flow** (D48 remainder).
- Captured `Protocol` is the **inner client** proto (h2-client → `h2`; h1-client + h2-origin → `http/1.1`).
- h2 client + h1 origin still serializes streams on one origin TCP (D44). Request trailers are dropped toward origin (stored on the flow; `labmitm_h2_trailer_dropped_total`). Origin h2 multiplexes when `protocols.http2.origin` and the inner leaf negotiated `h2` (D64); one CONNECT = one origin TCP.
- Replay of an h2 flow follows the **live** `protocols.http2.origin` flag (off → HTTP/1.1 origin-form with leading-`:` stripped; on → origin ALPN `h2` then `http/1.1` on one Dial). The one-shot origin TLS conn is closed after the response body is drained.
- `PUSH_PROMISE` is capture-only on the origin hop when `protocols.http2.capturePush` (default off, requires `origin`). Inner `EnablePush` stays 0; promised streams are stored as flows and are not forwarded or replayable. Flag-off RSTs the promised id toward origin immediately. Breakpoints pause the **stream**, not the TCP session.
- gRPC decode is opt-in `protocols.http2.grpcDecode`, fail-open, in-tree length-prefix + protobuf wire tree. grpc-web stays opaque.
- Handshake failure still does not blind-tunnel (D20). **D7 stands.**

## SOCKS residuals (when enabled)

- 1.1 `acceptSOCKS5` / `acceptSOCKS4` = CONNECT only, multiplexed on `listeners.proxy` (no extra bind). BIND / UDP ASSOCIATE / user-pass need their own flags.
- BIND (`acceptBind`) listens on the SOCKS control `LocalAddr()` IP only, never `:0` / `0.0.0.0` / `::`. Unspecified DST (`0.0.0.0:0` / `[::]:0`) is rejected (no Listen). BIND is always a raw tunnel (`intercepted=false`). No inner HTTP, no TLS MITM.
- UDP ASSOCIATE (`acceptUDPAssociate`) binds the relay on the control IP. First client datagram pins the client UDP source; FRAG ≠ 0 is dropped; inbound origin floods are capped. No TLS intercept, no QUIC, no orig-dest UDP.
- User-pass (`acceptUserPass`) is fail-closed RFC 1929 (no NO AUTH fallback). GSSAPI is never selected. Credentials are file refs, not Canonical, not a network boundary. Default bind remains `127.0.0.1:8888` (D10).
- Peek runs in a per-conn goroutine; Accept does not stall.
- Flags off keep 1.0 SOCKS-close (`reason="socks"`). `acceptSOCKS5` without `acceptBind` keeps BIND at `05 07`. `acceptSOCKS5` without `acceptUDPAssociate` keeps UDP at `05 07`.
- Same CIDR guards and `gate.acquire` as HTTP CONNECT. Hairpin includes live BIND listen ports and UDP associate ports. IMDS deny does not Dial or Listen.

## Compat residuals (when enabled)

- Management listener only. Same bearer as `/v1`. Cookie mutations still require CSRF.
- List is a JSON **array** of the newest 200 flows; `X-LabMITM-Truncated: true` when more exist. Native `/v1/flows` is the paginated API.
- Disabled prefix is `404` (SPA cannot swallow it). No new MCP tools. `/compat` is **not** on `catalog()`. Compat does not grow a frames or gRPC array.

## Not a public edge proxy (unchanged)

- No HTTP `Proxy-Authorization`. The HTTP hop is unauthenticated; SOCKS user-pass is opt-in (`acceptUserPass`) and is **not** a network boundary. Publishing `:8888` on a LAN is an operator choice with documented risk.
- Intercept **breaks origin mTLS and certificate pinning**.
- Not a general attack tool. No fuzzer, payload generator, SSL-strip, or exploit UX.
- Default standalone binds stay loopback `127.0.0.1:8888` / `127.0.0.1:8088` (D10). The lab overlay is the place that publishes `:8888`/`:8088`.
- Generate-mode CA rotates on every restart/reset. Operators who need a stable CA use `tls.ca.mode: files`.
- Default metadata CIDRs are AWS/GCP IPv4 + AWS IPv6 IMDS. Alibaba `100.100.100.200/32` and RFC1918 are **not** default-deny (lab SUTs).
- HTML preview of captured pages is escaped text (optional sandboxed iframe is off by default).
- WebSocket frames: flag-off is 101 + copy; flag-on is `protocols.websocket.inspectFrames` (D67). Inner Extended CONNECT websocket is `protocols.http2.extendedConnect` (D63).

## Store and control plane (unchanged)

- Store-full still forwards (capture is best-effort when the inspector is full).
- Single replica; no shared flow store.
- MCP clients requiring OAuth PRM cannot authorize. MCPJungle needs `allowLegacyClients: true` (family-doc reason; image SDK version not re-measured here).
- MCP protocol is **2026-07-28**. `mcp-stdio` is a developer adapter, not an image entrypoint.
- Management is bearer-only (D6). Catalog id is **`labmitm`**. There is no predecessor mitmproxy service to preserve.

## Deployment (unchanged except orig-dest overlay)

- Healthcheck plane is HTTP `/v1/health/ready`. Ready still requires the proxy listener bound. Orig-dest ready is `OrigDestBound || OrigDestOff` (1.0 default is off).
- Dockerfile and `make test-container` are in-tree. The default image is not granted `NET_ADMIN`. This candidate does not publish a `ghcr.io/hilather/labmitm` digest, SBOM, or provenance.
- Application binaries built without ldflags report version `dev`.
- Overlay examples live in this repo. The lab pin is vendor tag **v1.1.0** + `labmitm:local` (not a GHCR digest). A later appliance tag will align vendored `examples/` with the lab-owned copy; do not bump the lab pin off **v1.1.0** for comments. Catalog id is **`labmitm`** (D18).

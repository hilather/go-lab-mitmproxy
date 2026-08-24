# Known limitations (1.1 residuals; 1.0 defaults)

Honest residual for LabMITM after the 1.1 opt-in workstreams (HTTP/2 inner+origin, SOCKS5/4 CONNECT, Linux original-destination REDIRECT, compat flow REST, inspector metadata). These are not defects hidden from the notes. They are product bounds, default-off flags, or work that is **not** claimed here.

Last reviewed: 2026-08-23

This file is the operator-facing residual list. The numbered pack still wins on conflict: [docs/01-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/01-architecture.md#residual-limitations). Current tag notes: [docs/releases/v1.1.1.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/releases/v1.1.1.md). Untagged 1.0 notes remain [docs/releases/v1.0.0-rc.1.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/releases/v1.0.0-rc.1.md) (HTTP/1.1-only hops, no SOCKS, no orig-dest, no compat path).

LabMITM is a **laboratory intercepting proxy**. It is **not a public** edge proxy and not an attack framework. It never wraps, vendors, or execs Python mitmproxy.

## 1.0 defaults remain the process defaults

New public fields are additive `labmitm.dev/v1alpha1` and **default off**. An empty `spec: {}` is still a 1.0 process: HTTP/1.1 on every hop, SOCKS peek-close, no original-destination listener, no `/compat` routes, loopback binds.

| Surface | Default (1.0) | Opt-in (1.1, Reset-only except as noted) |
|---|---|---|
| Client-facing proxy hop (`:8888`) | HTTP/1.1 absolute-form + CONNECT. `PRI * HTTP/2.0` hard close | **Unchanged.** No h2c on the cleartext proxy port |
| Inner + origin ALPN | `http/1.1` only. Inner `PRI` → `Error=http2_inner` | `protocols.http2.enabled: true` (inner + origin only) |
| SOCKS on `listeners.proxy` | Peek `0x04`/`0x05` → close | `acceptSOCKS5` / `acceptSOCKS4` |
| Original destination | Unbound. Ready bit `OrigDestOff` | `listeners.originalDestination.enabled` (Linux REDIRECT) |
| Compat flow REST | Effective prefix `404` `not_found` | `compat.flowREST.enabled` (default prefix `/compat`) |
| Standalone binds | `127.0.0.1:8888` / `127.0.0.1:8088` (D10) | Empty orig-dest address → `127.0.0.1:8890` when enabled |
| Image | `USER 65532:65532`, `cap_drop: ALL`, no `NET_ADMIN` | **Unchanged.** iptables is sidecar/host only |

**Reset-only flags (D51).** Turning on SOCKS, HTTP/2, orig-dest, or compat requires a Reset (or process restart). There is no `replaceProtocols` / `replaceCompat` / `replaceProxyAccept`. `maxConcurrentStreams` is the exception: it rides `replaceAdmission` and applies to **new** TCP sessions only. Listener **addresses** stay reset-only.

Legal YAML names are camelCase (`acceptSOCKS5`, `originalDestination`, `protocols.http2`, `compat.flowREST`). Reserved keys (`socks*`, `tproxy`, `transparent`, `mitmproxy*`, `reverseproxy`, …) stay forbidden. `accept-socks5` fails KnownFields.

## This tree versus what is not tagged

1.1 workstreams are in this branch. What is **not** claimed:

| In this tree | Not this tree / not this product |
|---|---|
| Opt-in HTTP/2 inner+origin, SOCKS5/4 CONNECT, Linux orig-dest REDIRECT, compat flow REST, inspector metadata | HTTP/3 / QUIC; TPROXY appliance; reverse-proxy; Python mitmproxy |
| First-party flow-inspector SPA | mitmproxy mitmweb / Python addon UI |
| Overlay examples in this repo | mcp-integration-lab compose pin lives in that repo (vendor **v1.1.0** + `labmitm:local`; not a GHCR digest) |

**Catalog id is `labmitm` (D18).** Lab compose-in is vendor tag **v1.1.0** + image `labmitm:local`. A later appliance tag will align vendored `examples/` with the lab-owned copy; do not bump the lab pin off **v1.1.0** for comments.

## Still out of 1.1 (non-goals)

- **HTTP/3 / QUIC.** No QUIC listener, no `h3` ALPN, no datagrams.
- **Python VM / wrap.** No addon VM, no mitmweb SPA clone, no mitmproxy `.mitm` dumpfile, no CLI flag clone (`--mode`, `--set`, `--listen-host`). Do not wrap, vendor, or exec Python `mitmproxy` / `mitmdump` / `mitmweb`.
- **TPROXY in the appliance.** `tproxy` stays reserved. No `IP_TRANSPARENT`, no `CAP_NET_ADMIN` on the default image. Transparent intercept is Linux **REDIRECT + `SO_ORIGINAL_DST`** on a separate listener (sidecar/host iptables).
- **Reverse-proxy / ingress.** `reverseproxy` stays reserved. LabMITM is a forward proxy (+ optional orig-dest).
- **Windows / macOS original-destination.** Linux-only (`SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST`). Non-linux `enabled: true` fails `Start` closed and binds nothing.
- **Compat subset, not mitmproxy 11.** List/get/delete/clear/replay + raw content only. Out: mitmweb, dumpfile, CLI flags, addon, HTTP Basic, PUT mutate, UUID ids, filter DSL, HAR export. Headline: “LabMITM compat flow REST (mitmproxy-inspired subset).” Contract: [examples/compat/flow-rest-contract.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/compat/flow-rest-contract.md).
- **HTTP/2 or h2c on the client-facing cleartext proxy port.** `PRI * HTTP/2.0` on `:8888` **and** on `:8890` is a hard close.
- **HTTP/2 CONNECT to the proxy** (RFC 9113 §8.5) and Extended CONNECT (RFC 8441), including on the inner hop. Inner `:method=CONNECT` / `:protocol` is RST `PROTOCOL_ERROR`, no flow.
- **gRPC protobuf codec.** gRPC is HTTP/2 headers + DATA only.
- **SOCKS UDP ASSOCIATE, GSSAPI, username/password.** NO AUTH (`0x00`) only. BIND is 1.2 opt-in (`acceptBind`, default off); flag-off SOCKS5 BIND stays `05 07`.
- **WebSocket frame inspect.** `101` + bidirectional copy. Websocket Upgrade on an h2 inner session is rejected.
- **HTTP Basic on management (D6).** `Authorization: Basic` is 401 Bearer.
- **Public CA, SSL-strip, exploit/fuzzer UX, chaos engine, durable flow-directory, multi-replica store.**
- **Docker `-p 8890:8890` as “transparent mode.”** Publishing `8890` is not transparent (D50).
- **`labmitm send` / live apply of 1.1 flags / HAR export.**

## Original-destination topologies (D50)

Supported **only**:

1. **Shared netns:** SUT uses `network_mode: service:labmitm`. A sidecar (not the appliance) has `CAP_NET_ADMIN` and installs iptables/nft REDIRECT. labmitm stays UID `65532`, `cap_drop: ALL`.
2. **Host network:** labmitm `--network host` (still UID 65532) + **host** iptables REDIRECT to `127.0.0.1:8890`.

**Not supported:** Docker published-port DNAT to `:8890`. `SO_ORIGINAL_DST` then sees the container dest (often `:8890`) → direct-connect close or hairpin.

Overlay: [examples/compose.originaldest.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/compose.originaldest.yaml). Do not redirect 8088, 8888, 8890, or 9090. REDIRECT must skip UID `65532` on OUTPUT or dest-IP Dial hairpins back to `:8890`. `make test-container` never requires `NET_ADMIN`.

## HTTP/2 residuals (when enabled)

- Inner + origin hops only. Client-facing `:8888` / orig-dest cleartext stay HTTP/1.1.
- Captured `Protocol` is the **inner client** proto (h2-client → `h2`; h1-client + h2-origin → `http/1.1`).
- h2 client + h1 origin serializes streams on one origin TCP. Request trailers are dropped toward origin (stored on the flow; `labmitm_h2_trailer_dropped_total`).
- Replay of an h2 flow is HTTP/1.1 origin-form; leading-`:` names are stripped.
- `PUSH_PROMISE` is not captured. Breakpoints pause the **stream**, not the TCP session.
- Handshake failure still does not blind-tunnel (D20). **D7 stands.**

## SOCKS residuals (when enabled)

- CONNECT multiplexed on `listeners.proxy` (no extra bind). BIND (`acceptBind`) listens on the SOCKS control `LocalAddr()` IP only, never `:0` / `0.0.0.0` / `::`. Unspecified DST (`0.0.0.0:0` / `[::]:0`) is rejected (RFC residual).
- BIND is always a raw tunnel (`intercepted=false`). No inner HTTP, no TLS MITM.
- Peek runs in a per-conn goroutine; Accept does not stall.
- Flags off keep 1.0 SOCKS-close (`reason="socks"`). `acceptSOCKS5` without `acceptBind` keeps BIND at `05 07`.
- Same CIDR guards and `gate.acquire` as HTTP CONNECT. Hairpin includes live BIND listen ports. IMDS deny does not Dial or Listen.

## Compat residuals (when enabled)

- Management listener only. Same bearer as `/v1`. Cookie mutations still require CSRF.
- List is a JSON **array** of the newest 200 flows; `X-LabMITM-Truncated: true` when more exist. Native `/v1/flows` is the paginated API.
- Disabled prefix is `404` (SPA cannot swallow it). No new MCP tools. Catalog stays 30 `/v1` rows.

## Not a public edge proxy (unchanged)

- No Proxy-Authorization. The proxy data plane is unauthenticated; publishing `:8888` on a LAN is an operator choice with documented risk.
- Intercept **breaks origin mTLS and certificate pinning**.
- Not a general attack tool. No fuzzer, payload generator, SSL-strip, or exploit UX.
- Default standalone binds stay loopback `127.0.0.1:8888` / `127.0.0.1:8088` (D10). The lab overlay is the place that publishes `:8888`/`:8088`.
- Generate-mode CA rotates on every restart/reset. Operators who need a stable CA use `tls.ca.mode: files`.
- Default metadata CIDRs are AWS/GCP IPv4 + AWS IPv6 IMDS. Alibaba `100.100.100.200/32` and RFC1918 are **not** default-deny (lab SUTs).
- HTML preview of captured pages is escaped text (optional sandboxed iframe is off by default).
- No WebSocket **frame** inspect (101 + bidirectional copy only).

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

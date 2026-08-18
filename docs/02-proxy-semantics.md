# Proxy Semantics

Status: Proposed normative behavior
Owners: Proxy, TLS
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0002, 0008, 0009, 0011

LabMITM is an intercepting proxy, not a general HTTP library wrapper. This document is the accept/reject and mode table. Implementation: PROXY-001, TLS-001, H2-001, WS-001, MODE-001.

## Modes (1.0)

`spec.proxy.modes` is a non-empty sequence. Each entry binds one listener. Duplicate bind addresses fail validate.

| Mode | Listen default | Client handshake | Upstream |
|---|---|---|---|
| `regular` | `:8080` | HTTP proxy + `CONNECT` | Request URL / CONNECT target |
| `reverse` | mode-specific `@host:port` | Origin-form HTTP(S) as a server | Fixed `spec` target |
| `socks5` | `:10800` | SOCKS5 (no UDP associate in 1.0) | SOCKS dest |
| `upstream` | `:8080` unless overridden | Same as regular | Next HTTP proxy `spec` |

Syntax (mitmproxy-compatible strings, stored structured in YAML):

```text
regular[@listen_host:listen_port]
socks5[@listen_host:listen_port]
reverse:http://host:port[@listen]
reverse:https://host:port[@listen]
upstream:http://host:port[@listen]
upstream:https://host:port[@listen]
```

1.0 **rejects** at validate: `transparent`, `local`, `wireguard`, `tun`, `reverse:http3:`, `reverse:quic:`, `reverse:dns:`, `reverse:udp:`, `reverse:dtls:`. Message: `unsupported in 1.0; see ADR 0009 / 0011`. `reverse:tcp:` and `reverse:tls:` are 1.0 **optional** only if PROXY-001 lands raw TCP pass-through tests; otherwise reject until a follow-up ADR. Default program: reject raw TCP reverse in 1.0; HTTP(S) reverse only.

`connection_strategy`: `eager` (default) or `lazy`. Lazy defers upstream connect so server replay works offline.

## HTTP/1.1 regular mode

### Absolute-form requests

Non-CONNECT requests SHOULD be absolute-form (`GET http://host/path HTTP/1.1`). Origin-form is accepted when `Host` is present (common clients). Missing Host on origin-form → 400.

### CONNECT

1. Client `CONNECT host:port HTTP/1.1`.
2. LabMITM replies `200 Connection Established` **without** contacting upstream first when `connection_strategy=lazy` or when the flow is intercepted before upstream.
3. Bytes after CONNECT are TLS ClientHello or raw HTTP (http-over-proxy).
4. If TLS ClientHello: intercept unless `ignore_hosts` matches; then mint leaf (TLS-001) and speak HTTP/1 or HTTP/2 on the decrypted stream.
5. If `ignore_hosts` matches: splice bytes upstream without interception (no flow body unless `show_ignored_hosts`).

CONNECT to a non-allowed destination class: see [docs/08-security-architecture.md](08-security-architecture.md) (`block_global`, `block_private`).

### Hop-by-hop headers

Strip on both request and response: `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization` (after proxy-auth addon), `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade` (except when WS-001 is completing a WebSocket handshake). `Proxy-Connection` is treated as `Connection`.

### HTTP versions

| Client | Upstream | 1.0 behavior |
|---|---|---|
| HTTP/1.0 | HTTP/1.1 | Translate; add `Connection: close` if client is 1.0 |
| HTTP/1.1 | HTTP/1.1 | Default |
| HTTP/1.1 | HTTP/2 | If `http2: true` and ALPN `h2` |
| HTTP/2 | HTTP/1.1 | Translate if upstream has no h2 |
| HTTP/2 | HTTP/2 | H2-001 |

HTTP/0.9 is rejected.

### Body limits

`spec.proxy.bodySizeLimit` (optional). Exceeding: store error on the flow, respond 413 to client when the request is inbound, cut upstream response. `stream_large_bodies` streams without storing unless `store_streamed_bodies`.

## Reverse mode

- Client speaks origin-form to LabMITM as if it were the origin.
- Upstream URL is the mode spec. `keep_host_header` (default false) rewrites `Host` to the target host.
- `keep_alt_svc_header` default false: strip `Alt-Svc` so clients do not bypass to HTTP/3 in 1.0.
- TLS on the client side is a distinct bind (`reverse:https://`).

## SOCKS5

- Methods: no-auth (`0x00`) always. Username/password (`0x02`) when `spec.proxy.proxyauth` is set.
- Commands: CONNECT only. BIND and UDP ASSOCIATE → SOCKS failure.
- IPv4, IPv6, domain dest.

## Upstream proxy mode

LabMITM uses HTTP `CONNECT` (for HTTPS) or absolute-form (for HTTP) to the next proxy. `upstream_auth` adds `Proxy-Authorization: Basic`.

## Ignore / allow hosts

`ignore_hosts` and `allow_hosts` are RE2 lists matched against hostname **or** IP as documented by mitmproxy. If `allow_hosts` is non-empty, it is an allowlist (opposite of ignore). Ignore skips TLS intercept. Regular mode: “only SSL traffic is ignored” for hostname matches — preserve that mitmproxy quirk and test it.

## Protocol flags

| Option | Default | 1.0 |
|---|---|---|
| `http2` | true | Implemented H2-001 |
| `http3` | false in schema for 1.0 (mitmproxy true) | Reject `true` until H3-001 |
| `websocket` | true | WS-001 |
| `rawtcp` | false in 1.0 | Reject `true` |
| `validateInboundHeaders` | true | Must not be disable-able without `mitm.admin` + audit; image default true |

## WebSocket (WS-001)

After HTTP/1.1 (or H2 CONNECT in 1.1 if needed) Upgrade:

- Capture each message as `WSMessage{ Direction, Opcode, Payload, Timestamp, Length }`.
- Honor `websocket: false` by refusing Upgrade (HTTP 400/426).
- Intercept can hold the handshake; message-level intercept is 1.0 if FILT-001 + STORE-001 land `flows.resume` on WS; otherwise handshake-only intercept in 1.0 and message hold in 1.1. **Program decision:** 1.0 supports message capture and kill; per-message intercept/modify is required for parity — WS-001 must implement it.

## HTTP/2 (H2-001)

- ALPN: offer `h2`, `http/1.1` on intercepted TLS.
- Translate to HTTP/1.1 upstream when upstream ALPN is not h2.
- `http2_ping_keepalive` default 58s.
- `normalize_outbound_headers`: lowercase HTTP/2 names; warn in logs.
- SETTINGS and HPACK stay inside the `internal/proxy/h2` adapter (`x/net/http2`). Types do not leak.

## Timeouts

| Knob | Default |
|---|---|
| `tcp_timeout` | 600s idle |
| Session headers-timeout | 60s |
| Body idle | 180s |

## Proxy authentication

`spec.proxy.proxyauth`:

- `off` (default lab)
- `basic` with `username` + `passwordFile`
- `any` (accept any user/pass) — **forbidden in the hardened image default**; allowed only when `management.auth.mode` is `dev-loopback-unauth` or an explicit `dangerAllowAnyProxyAuth: true` (audit, tests).

LDAP proxyauth is 1.1 (LabLDAP exists in the lab; do not reimplement LDAP client in 1.0).

## Onboarding app

When `spec.proxy.onboarding.enabled` (default true), HTTP requests to `spec.proxy.onboarding.host` (default `mitm.it`) are served locally:

- Platform CA download links (PEM, P12, CER)
- Does not serve the CA **private key**
- Works in reverse and regular modes

This is data-plane, not a management capability.

## Interop targets (1.0)

Must pass integration tests:

- `curl -x http://127.0.0.1:8080 --cacert ca.pem https://example.test/`
- `curl -x http://127.0.0.1:8080 http://example.test/`
- Go `net/http` with `http.ProxyURL`
- HTTP/2 via curl `--http2`
- WebSocket via `nhooyr.io/websocket` or stdlib after WS-001
- SOCKS5 via `curl --socks5-hostname`
- Reverse mode: curl to LabMITM origin, backend is httptest

Use `internal/proxytest` origin servers; do not depend on the public Internet in CI.

## Related documents

- TLS: [docs/23-tls-and-certificates.md](23-tls-and-certificates.md)
- Filters: [docs/24-filter-language.md](24-filter-language.md)
- Addons: [docs/22-addon-pipeline.md](22-addon-pipeline.md)

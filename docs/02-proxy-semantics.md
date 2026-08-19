# Proxy Semantics

Status: Proposed normative behavior
Owners: Proxy, Architecture
Last reviewed: 2026-08-19 (accept mux D42 + http2x codec)
Related ADRs: 0002, 0009, 0010

Implementation lives in `internal/proxy` (listener, session, CONNECT, resolve-then-guard) and `internal/httputilx` (hop-by-hop strip). No third-party proxy library. Do not use `httputil.ReverseProxy`. See [docs/adr/0002-in-tree-http-forward-proxy.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0002-in-tree-http-forward-proxy.md).

Completed flows (including `TLSInfo` when intercept ran) are inserted into `store.Memory`. `fullPolicy: reject` drops capture only; the client hop still succeeds. `proxy.NewNull` remains a test fallback. TLS intercept is implemented: `intercept: false` (or a non-listed port) is a raw tunnel; `intercept: true` on a listed port mints a leaf and runs the inner HTTP/1.1 session. Handshake failure does not fall back to a blind tunnel (D20). Request- and response-phase rules (`internal/rules`) run after parse and after upstream headers. `rules.enabled` default-off matches nothing.

This document is the accept/reject table. Do not invent additional request classes, replies, or limits without an ADR.

## Listener

Accept never peeks (D42). `net.Listen("tcp", addr)` feeds a per-conn dispatch goroutine; HTTP is handed to `http.Server` through `chanListener`:

```go
var proto http.Protocols
proto.SetHTTP1(true) // HTTP/2 off
rawLn, err := net.Listen("tcp", addr)
httpLn := newChanListener(rawLn.Addr()) // Accept / Close / Addr
srv := &http.Server{
    Handler:           proxyHandler, // not the management mux
    ReadHeaderTimeout: 10 * time.Second,
    IdleTimeout:       spec.Admission.IdleTimeout, // default 120s
    MaxHeaderBytes:    1 << 20,
    Protocols:         &proto,
    TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
    ErrorLog:          slogDiscard,
}
// go srv.Serve(httpLn)
// go acceptLoop(rawLn): Accept immediately; go dispatchConn(c)
// dispatchConn: SetReadDeadline(HeaderTimeout); peek 1 byte (replay buffer).
// 0x04 / 0x05 → close; metric reason="socks" (acceptSOCKS5/4 off = 1.0).
// else → httpLn.Push(c)  // HTTP/1.1 including PRI
```

SOCKS detection is **not** possible in the Handler and **must not** run on the Accept goroutine (a silent peer would stall the next client until `HeaderTimeout`). Peeked bytes are the subsequent Read source. HTTP/2 preface **is** handled in the Handler (`Method == "PRI"`). `chanListener.Close` unblocks Accept with `net.ErrClosed` and closes queued conns.

Shutdown order (D42): `accepting=false` → close `rawLn` → wait acceptLoop → close in-peek dispatch conns → wait dispatch goroutines → `chanListener.Close` → `http.Server.Shutdown` → hijack drain.

## Request classification

| Client request | 1.0 behavior |
|---|---|
| Absolute-form `GET http://host[:port]/path HTTP/1.1` | Forward HTTP/1.1 to origin (origin-form on the upstream hop). Default port **80**. Capture. |
| Absolute-form `https://…` | `400` `validation_failed` with remediation “use CONNECT”. Metric `reason="absolute_https"`. |
| `CONNECT host:port HTTP/1.1` | **Hijack** (D19). Missing port → `400`. |
| Origin-form (`GET /path`) | `400` `validation_failed` (`absolute-form or CONNECT required`). |
| `PRI * HTTP/2.0` | Close connection. Metric `reason="http2"`. |
| First byte `0x05` / `0x04` (per-conn peek; `acceptSOCKS5`/`acceptSOCKS4` off) | Close. Metric `reason="socks"`. |
| HTTP/1.0 | Accept if absolute-form `http://` or CONNECT with port; respond HTTP/1.1. |

Authority resolution:

1. **CONNECT** request-target **must** be `host:port` (RFC 9110). Missing port → `400`. No default-to-443.
2. **Absolute-form `http://`**: host from `req.URL.Host`; default port **80** if omitted. Scheme `https` is rejected.
3. `Host` header must be present for HTTP/1.1 non-CONNECT (stdlib enforces).

Hop-by-hop headers stripped on both legs: `Proxy-Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Proxy-Authorization`. `Connection` is stripped **except** when forwarding a WebSocket upgrade. `Upgrade` is kept only on that path.

## CONNECT Hijack and inner session

Normative for every `CONNECT` (D19). Tests: two GETs on one CONNECT; “forgot to hijack” must **not** appear as `400` on ClientHello (`testdata/proxy/connect-two-gets.txt`, `connect-hijack.txt`).

```text
1. Handler sees Method == CONNECT.
2. Require Hijacker. Hijack() BEFORE writing the body and BEFORE return.
3. Admit + resolve-then-guard on CONNECT host:port (and later SNI).
4. Dial the selected allowed IP:port (no second resolve).
5. Write "HTTP/1.1 200 Connection Established\r\n\r\n" on the hijacked conn.
6. Decide intercept (D20):
   - intercept && hostMatches && port in spec.tls.ports (default {443})
     → tls.Server on client + tls.Client on upstream (internal/tlsmitm).
     Handshake failure → close both, store metadata flow Error=tls_handshake
     or Error=upstream_tls. Do NOT fall back to a blind tunnel.
   - otherwise → bidirectional copy; metadata-only flow (Protocol=connect,
     intercepted=false). No inner HTTP parse.
7. Intercept success: inner HTTP/1.1 session.
```

**Inner HTTP/1.1 (intercepted CONNECT only):**

- One CONNECT = **one** upstream TCP + **one** upstream TLS conn. Do **not** put this conn in the cleartext `Transport` idle pool.
- Serialized inner requests: `http.ReadRequest` on the client `tls.Conn`, then `Transport.RoundTrip` with a one-shot `DialContext` that returns the already-handshaked upstream `tls.Conn`.
- Each inner request is **one flow**.
- Inner knobs: HTTP/1 only until the HTTP/2 capture workstream. Inner `PRI` → close both sides, `Error=http2_inner` (flag off **and** flag on until capture is wired). Handshake ALPN is taken from the session snapshot (D46); default/flag-off is `http/1.1`.
- Client keep-alive on the inner TLS session is allowed.
- Inner `Upgrade: websocket` + `101` uses the same 101 + bidirectional copy as cleartext (no frame inspect). RoundTrip failure writes `502` and closes both TLS sides (no keep-alive loop).

## Cleartext forward

Upstream request is origin-form. Use `http.Transport.RoundTrip` **only** — never `http.Client` / `Client.Do` (D21). Process-wide cleartext Transport:

- `DisableCompression: true`
- HTTP/2 disabled; `TLSNextProto` empty
- `Proxy: nil` (never honor `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`)
- `DialContext` from `internal/proxy/dial.go` (`dialTCP` / `dialPinned`; the only Dial site; pins the resolved IP)
- Timeouts from admission spec
- `MaxIdleConnsPerHost=8` for **cleartext absolute-form only**. CONNECT/TLS sessions do **not** use this pool.

`Expect: 100-continue`: **strip** from the forwarded request; never generate a `100` response.

## Stream vs mutate (bodies)

Two paths, chosen **after** request-phase rules match (and again after response headers for response-phase rules):

| Path | When | Behavior |
|---|---|---|
| **Capture-only** | `rules.enabled: false`, or the winning action is not `body` / `status` / `drop` / `breakpoint` | `io.TeeReader` into a buffer capped at `maxBodyBytes`; remainder is copied to the peer with a 64 KiB stack buffer and **not** stored (`Truncated=true`). |
| **Mutating** | Winning action is `body`, `status`, `drop` (before flush), or `breakpoint` | Buffer up to `maxBodyBytes`. Beyond that: fail-closed — skip the `body` replace (`action="body_skipped"`); `status`/`drop`/`breakpoint` still apply to headers. Data-plane continues unmodified for the body. |

`drop` / `status` on the **response** path is illegal after the client has been written any body byte; if the capture-only path already flushed, the action is skipped and counted `action="late_skip"`.

RSS budget:

```
resident            ≤ maxBytes                          # default 256 MiB
reservedInFlight    ≤ maxInFlightBytes                  # default 64 MiB
streamSlack         = 64KiB × maxInFlight               # default 4 MiB
worstRSS            ≈ 256 + 64 + 4 + 64 = 388 MiB
```

## WebSocket / Upgrade (1.0)

If the request has `Upgrade: websocket` (case-insensitive) **and** `Connection` contains `Upgrade` (cleartext absolute-form **or** an inner request on an intercepted CONNECT):

1. Keep `Upgrade` and rewrite `Connection` to the single token `Upgrade`.
2. Capture request headers (and body if small / capture-only).
3. `RoundTrip` the upgrade.
4. On `101`, set `flow.Protocol = "websocket"`, stop body capture, hijack both legs, bidirectional copy. Do not decode frames.
5. Mutating rules do **not** apply after `101`.
6. Replay of `Protocol=websocket` is rejected.

If `Upgrade` is present without `Connection: Upgrade`, treat as a normal request.

## Target guards (D16) — resolve then Dial

Guards run on **resolved IPs**, not only the request-target string. `allowHosts` / `denyHosts` match the **CONNECT host** (or absolute-form host) **and**, after a successful ClientHello, the **SNI**. If SNI is present and differs from CONNECT host, **both** must pass; either failing is `target_denied`. Literal IPs skip the name glob (they still hit CIDR guards).

```text
parse authority → host, port
if host is a literal IP:
    addrs = [host]
else:
    if denyHosts matches host → reject (no lookup)
    if allowHosts non-empty && !allowHosts.matches(host) → reject (no lookup)
    addrs = Resolver.LookupIP(ctx, "ip", host)
    if lookup fails → 502 / Error=dns; do not Dial
for each addr in addrs:
    if denyCloudMetadata && addr in metadataCIDRs → mark denied
    if denyLinkLocal && addr in linkLocalCIDRs → mark denied
    if addr is loopback && !allowLoopback → mark denied
    else mark allowed
if any addr is denied → reject the whole name (Error=target_denied).
if no addr remains allowed → reject
pick first allowed addr (stable: IPv6 if present else IPv4)
Dial(network, net.JoinHostPort(selected.String(), port))
    with Dialer{Resolver: nil}
after ClientHello, if SNI set: re-check allowHosts/denyHosts on SNI
```

| Guard | Default | Effect |
|---|---|---|
| `proxy.targets.denyCloudMetadata` | `true` | Reject `169.254.169.254/32`, `fd00:ec2::254/128` |
| `proxy.targets.denyLinkLocal` | `true` | Reject `169.254.0.0/16`, `fe80::/10` |
| `proxy.targets.allowLoopback` | `true` | Allow `127.0.0.0/8`, `::1` |
| `proxy.targets.allowHosts` | `[]` (empty = any name) | Exact or `*.suffix` on CONNECT host **and** SNI |
| `proxy.targets.denyHosts` | `[]` | Always-deny list wins over allow |

Reject → `403 Forbidden` (or CONNECT 403 after Hijack if the 200 has not been written; if 200 already went out, close). Store `Error=target_denied`. Do not Dial.

**Residual CIDRs (documented, not default-deny in 1.0):** Alibaba IMDS `100.100.100.200/32`; RFC1918 and ULA `fc00::/7` are **default-allow** so lab SUTs keep working. Operators who publish `:8888` on a LAN should set `allowHosts`.

## Admission

| Limit | Default |
|---|---|
| `maxSessions` | 256 |
| `maxSessionsPerIP` | 32 |
| `maxInFlight` | 64 |
| `maxInFlightBytes` | 64 MiB |
| `sessionTimeout` | 10m |
| `idleTimeout` | 120s |
| `headerTimeout` | 10s |
| `dialTimeout` | 10s |
| `upstreamTimeout` | 60s |

Over admission → `429` (HTTP) or CONNECT `429` (unusual; use `503` for CONNECT if the response has not started). Metric `labmitm_proxy_rejected_total{reason="admission"}`. Admission `maxInFlight` includes paused breakpoint sessions.

`sessionTimeout` is an absolute deadline on hijacked CONNECT and WebSocket tunnels (default 10m). `idleTimeout` refreshes on each copied byte on those legs and is also `http.Server.IdleTimeout` on the cleartext hop. `headerTimeout` also bounds the per-conn first-byte peek. `Shutdown` (D42): `accepting=false` → close `rawLn` → wait acceptLoop → close in-peek dispatch conns → wait dispatch goroutines (ctx-bounded; force-close remaining peeks) → `chanListener.Close` → `http.Server.Shutdown` → wait for hijacked sessions up to `--shutdown-timeout`, then force-close them.

## Related documents

- TLS intercept: [docs/03-tls-interception.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/03-tls-interception.md)
- Store: [docs/04-flow-store.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/04-flow-store.md)
- Rules: [docs/05-rules.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/05-rules.md)
- SOCKS / orig-dest: [docs/adr/0010-socks-and-original-destination.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0010-socks-and-original-destination.md)

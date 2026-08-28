# Proxy Semantics

Status: Proposed normative behavior
Owners: Proxy, Architecture
Last reviewed: 2026-08-28 (D69 silent/hang/redirect; D72–D74 websocket frame rules; HTTP proxy 407 D76)
Related ADRs: 0002, 0009, 0010, 0012, 0013, 0014, 0015, 0016

Implementation lives in `internal/proxy` (listener, session, CONNECT, resolve-then-guard) and `internal/httputilx` (hop-by-hop strip). No third-party proxy library. Do not use `httputil.ReverseProxy`. See [docs/adr/0002-in-tree-http-forward-proxy.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0002-in-tree-http-forward-proxy.md).

Completed flows (including `TLSInfo` when intercept ran) are inserted into `store.Memory`. `fullPolicy: reject` drops capture only; the client hop still succeeds. `proxy.NewNull` remains a test fallback. TLS intercept is implemented: `intercept: false` (or a non-listed port) is a raw tunnel; `intercept: true` on a listed port mints a leaf and runs the inner HTTP session (HTTP/1.1, or HTTP/2 when `protocols.http2.enabled` and the inner ALPN is `h2`). Handshake failure does not fall back to a blind tunnel (D20). Request- and response-phase rules (`internal/rules`) run after parse and after upstream headers. `rules.enabled` default-off matches nothing.

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
// 0x05 && acceptSOCKS5 → serveSOCKS5 (replay peeked byte).
// 0x04 && acceptSOCKS4 → serveSOCKS4.
// else 0x04 / 0x05 → close; metric reason="socks" (1.0 default).
// else → httpLn.Push(c)  // HTTP/1.1 including PRI (0x50, same as POST)
```

SOCKS detection is **not** possible in the Handler and **must not** run on the Accept goroutine (a silent peer would stall the next client until `HeaderTimeout`). Peeked bytes are the subsequent Read source. HTTP/2 preface **is** handled in the Handler (`Method == "PRI"`). Peek stays **1 byte** (D49); do **not** peek 24 bytes of the HTTP/2 preface on `dispatchConn`. `chanListener.Close` unblocks Accept with `net.ErrClosed` and closes queued conns. `http.Server` stays HTTP/1.1-only (`Protocols` HTTP/2 off, including unencrypted). Do **not** enable stdlib `http.Protocols` HTTP/2.

When `listeners.originalDestination.enabled` is true (Linux only; default off), `Start` binds a **second** listener (empty address → `127.0.0.1:8890`, D38) and `http.Server.ConnContext` tags recovered dest. Non-linux `enabled: true` fails closed and binds **nothing**. iptables/nft REDIRECT is sidecar/host only; the default image stays UID 65532 without `NET_ADMIN` (D30, D50). Publishing `8890` is not transparent.

Shutdown order (D42): `accepting=false` → close `rawLn` → close orig-dest listener if bound → wait acceptLoop → close in-peek dispatch conns → closeBinds (BIND listens and UDP ASSOCIATE sockets) → wait dispatch goroutines → `chanListener.Close` → `http.Server.Shutdown` → hijack drain.

## Request classification

| Client request | 1.0 behavior |
|---|---|
| Absolute-form `GET http://host[:port]/path HTTP/1.1` | Forward HTTP/1.1 to origin (origin-form on the upstream hop). Default port **80**. Capture. Gate off (`protocols.absoluteForm.enabled` false) → `403` `forbidden` **before DNS/Dial**. Metric `reason="absolute_form"`. Orig-dest origin-form is **not** this flag. When `spec.proxy.httpAuth.enabled` (D76): after hop gates, **before** `resolveThenGuard`, missing/invalid `Proxy-Authorization` → `407` via `writeProxyAuthChallenge` (determinate `Content-Length`; no `Connection: close`). Metric `reason="proxy_auth"`. Post-`metrics.accept()`. |
| Absolute-form `https://…` | `400` `validation_failed` with remediation “use CONNECT”. Metric `reason="absolute_https"`. Unchanged even when `absoluteForm` is on. Not a 407 hop. |
| `CONNECT host:port HTTP/1.1` | **Hijack** (D19) only when proceeding to the tunnel. Missing port → `400` (auth not consulted; already accept+400). Gate off (`protocols.connect.enabled` false) → `403` `forbidden` **after** orig-dest D57, **before** Hijack / `metrics.accept()`. Metric `reason="connect"`. SOCKS CONNECT is **not** this flag. When `httpAuth.enabled` (D76) **contract (A):** check auth in `serveCONNECT` after `host:port` parse, **before Hijack**, post-`metrics.accept()`. 407 via `ResponseWriter` (not `writeProxyError`). Do not move `metrics.accept()`. |
| Origin-form (`GET /path`) on `:8888` | `400` `validation_failed` (`absolute-form or CONNECT required`). |
| Origin-form on orig-dest `:8890` with recovered dest | Legal (D31). Dial dest IP:port only (D57). |
| Tagged orig-dest `CONNECT` | `400`, no Dial. |
| Tagged orig-dest absolute-form (incl. `GET http://169.254.169.254/`) | Dial dest IP:port only; never `serveAbsolute` / never Dial Host. |
| `PRI * HTTP/2.0` on `:8888` **or** orig-dest | Flag-off (`protocols.http2.clientCleartext` false): close. Metric `reason="http2"`. **Before** `gate.acquire`. Flag-on: Hijack (D19) with no Write; leftover `SM\r\n\r\n` plus SETTINGS in `bufio.ReadWriter`; `gate.acquire` **once per TCP**; `http2x.ServeConn(..., PrefaceTail)`. Never return the conn to `http.Server`. |
| First byte `0x05` / `0x04` (per-conn peek; `acceptSOCKS5`/`acceptSOCKS4` off) | Close. Metric `reason="socks"`. |
| First byte `0x05` and `acceptSOCKS5: true` | SOCKS5 CONNECT. Peeked `0x05` is replayed. Method select: `acceptUserPass` false → NO AUTH (`0x00`) only; `acceptUserPass` true → RFC 1929 (`0x02`) only (never `0x00` even if offered). GSSAPI (`0x01`) is never selected. BIND if `acceptBind`; UDP ASSOCIATE if `acceptUDPAssociate`; else CMD `05 07`. |
| First byte `0x04` and `acceptSOCKS4: true` | SOCKS4/4a CONNECT. USERID discarded. BIND if `acceptBind` and CD=2; else CD≠1 → `91`. |
| HTTP/1.0 | Accept if absolute-form `http://` or CONNECT with port; respond HTTP/1.1. |

Authority resolution:

1. **CONNECT** request-target **must** be `host:port` (RFC 9110). Missing port → `400`. No default-to-443.
2. **Absolute-form `http://`**: host from `req.URL.Host`; default port **80** if omitted. Scheme `https` is rejected.
3. `Host` header must be present for HTTP/1.1 non-CONNECT (stdlib enforces).

Hop-by-hop headers stripped on both legs: `Proxy-Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Proxy-Authorization`. `Connection` is stripped **except** when forwarding a WebSocket upgrade. `Upgrade` is kept only on that path. Accepted `Proxy-Authorization` is never forwarded to origin.

### HTTP proxy 407 (D76)

Opt-in `spec.proxy.httpAuth` on `listeners.proxy` only ([ADR 0017](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0017-http-proxy-407.md)). Default-off. Live via `replaceHTTPAuth`. Empty realm materializes `labmitm-proxy` (must not equal management `Bearer realm="labmitm"`).

| Entry | 407? |
|---|---|
| HTTP/1.1 CONNECT / absolute-form `http://` | yes (after hop gates; CONNECT after port parse, before Hijack) |
| Client-facing h2c GET/POST | yes (`reconstructH2Request` copies headers; then `serveAbsolute`) |
| Client-facing h2c RFC 9113 CONNECT | yes (`h2cConnectRequest` copies `Stream.Headers`; return `Tunnel{Status:407}` — do **not** call `writeProxyAuthChallenge`). **Not** `protocols.connect` (HTTP/1.1 CONNECT 403 can coexist with h2c 407). |
| Absolute-form `https://`, origin-form on `:8888`, orig-dest, PRI flag-off, inner intercept, SOCKS, Replay, h2c Extended CONNECT (`:protocol=websocket`) | no |

`writeProxyAuthChallenge` writes HTTP/1.1 407, `Proxy-Authenticate: Basic realm="…"`, short `text/plain` body, mandatory `Content-Length`, omit `Connection: close`, no chunked. Do **not** reuse `writeProxyError` (that helper always closes and has no length). A 407 CONNECT stays with `http.Server` (D19). Flow `Status=407` `Error=proxy_auth` (no username/password). `rules` `action.status: 407` is a synthetic origin-like response after DNS — not this feature.

## SOCKS CONNECT (opt-in)

No third-party SOCKS library. `gate.acquire` runs after a valid CONNECT request is parsed and **before** Dial (same gate as `ServeHTTP`). Hairpin → SOCKS5 `05 02` / SOCKS4 `91`, no Dial. IMDS/link-local CIDR deny does not Dial `169.254.169.254`.

SOCKS5 method select ([ADR 0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) D60):

```text
NMETHODS=0
  → close, no 05 FF (1.1 greeting; same with acceptUserPass)
methods include 0x02 and acceptUserPass
  → write 05 02
  → read RFC 1929 VER=1 ULEN UNAME PLEN PASSWD
  → constant-time compare of SHA-256(len||username||len||password) against
    EVERY snapshot SOCKSUsers digest
  → 01 00 success or 01 01 failure + close (reason=socks_auth)
acceptUserPass and client did not offer 0x02
  → 05 FF (even if 0x00 was offered)
acceptUserPass false
  → existing NO AUTH only
GSSAPI (0x01) is never selected
```
Success BND: IPv4 or domain ATYP → `0.0.0.0:0`; IPv6 ATYP → `::` port 0. Then `shouldIntercept` → `serveInterceptConn` (no HTTP 200). Else bidirectional copy; metadata flow `Protocol=socks5|socks4`, `Via` matching, `Method=CONNECT`, `SOCKS.Command="connect"`. Intercepted inner flows copy `Via`/`SOCKS`. Matching YAML `userPass` `id` may appear on `SOCKSInfo.User`; username and password are never stored on the flow. GSSAPI is never selected. UDP ASSOCIATE is a separate flag (`acceptUDPAssociate`); flag-off stays `05 07`.

## SOCKS BIND (1.2, opt-in)

Requires `listeners.proxy.acceptBind` (default false, Reset-only, D58) **and** `acceptSOCKS5` or `acceptSOCKS4`. A 1.1 CONNECT-only config must not grow ephemeral listeners on upgrade. Flag-off keeps today: SOCKS5 BIND → `05 07` (`TestSOCKS5BindCommand`); SOCKS4 CD=2 → `91` (`TestSOCKS4CommandRejected`). `acceptSOCKS5` false is peek-close `reason=socks` with **no** reply.

RFC 1928 CMD `0x02`. SOCKS4 CD `0x02` shares semantics. BIND is **always a raw tunnel** (`intercepted=false`). No inner HTTP, no TLS MITM. Production `net.Listen` for BIND is `listenEphemeralTCP` in `internal/proxy` only (D68). Overlay examples stay flags-off.

```text
1. Parse DST.ADDR/DST.PORT. Unspecified (0.0.0.0:0 / [::]:0 / empty) → 05 02 / 91, no Listen.
2. gate.acquire (same as CONNECT) before Listen.
3. resolveThenGuard(DST). Denied → 05 02 / SOCKS4 91, no Listen. IMDS/link-local deny.
4. controlIP := unicast host of c.LocalAddr(); reject if unspecified / metadata / link-local.
   net.Listen("tcp", JoinHostPort(controlIP, "0")) — never ":0", never 0.0.0.0:0, never [::]:0.
   Track bind in the live hairpin set for the lifetime of the control conn.
5. First reply: BND = that same controlIP : boundPort (never IMDS / fe80:: / listeners.proxy.address / orig-dest listen).
6. Accept one inbound with deadline = sessionTimeout.
7. Guard peer IP (CIDR) AND membership in the resolved DST set. Mismatch → second reply failure, no tunnel.
8. Second reply success or failure. On success: bidirectional copy; capture
   Protocol=socks5|socks4, SOCKS.Command="bind", SOCKS.BND=advertised bind, intercepted=false.
9. Close listen; untrack hairpin; release gate.
```

RFC residual: unspecified DST is rejected (RFC 1928 allows unknown DST). FTP clients must name the expected peer. See [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/known-limitations.md).

Tests live in `internal/proxy/socks_test.go` (second inbound TCP). `proxytest.PlayTranscript` cannot Accept the peer — do not use it for BIND success. Required: BIND success two-reply; IMDS DST no Listen; unspecified DST no Listen; hairpin BND; wrong-peer Accept second-reply `05 02` (no tunnel); SOCKS4 BIND; `acceptSOCKS5` on + `acceptBind` off still `05 07`.

Shutdown `closeBinds` unblocks BIND `Accept` before waiting dispatch/hijack goroutines (D42); BIND must not wait out `sessionTimeout` on process stop.

See [docs/adr/0012-protocol-expansion-12.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) D58.

## SOCKS UDP ASSOCIATE (1.2, opt-in)

Requires `listeners.proxy.acceptUDPAssociate` (default false, Reset-only, D59) **and** `acceptSOCKS5`. Datagram relay is a different threat than TCP CONNECT; a 1.1 CONNECT-only config must not grow a UDP socket on upgrade. Flag-off keeps today: SOCKS5 UDP ASSOCIATE → `05 07` (`TestSOCKS5UDPCommand`). `acceptSOCKS5` false is peek-close `reason=socks` with **no** reply. SOCKS4 has no UDP ASSOCIATE.

RFC 1928 CMD `0x03`. No TLS intercept, no QUIC, no orig-dest UDP. Production `ListenUDP` / `DialUDP` live in `internal/proxy` only (D68). Overlay examples stay flags-off.

```text
1. Parse DST in the ASSOCIATE request (often 0.0.0.0:0). That DST is NOT the only
   future dest; unspecified ASSOCIATE DST is legal (unlike BIND).
2. gate.acquire (control conn is one session; datagrams do not each acquire).
   listenUDP on control LocalAddr IP + port 0 (never 0.0.0.0/::). Track in the
   live hairpin set (same set BIND uses).
3. Reply BND = controlIP : udpPort (same advertisement rules as BIND).
4. First client datagram pins the client UDP source; later packets from any
   other source are dropped. The RFC ASSOCIATE request UDP port is not a
   second allowed source.
5. While control TCP is open:
     parse RSV RSV FRAG ATYP DST.ADDR DST.PORT DATA
     FRAG≠0 → drop (no reassembly)
     if ATYP domain: pin selected IP for this dest on first use (LookupIP +
       deny every A/AAAA once); reuse pin; no second resolve
     if ATYP literal: denyIP only
     hairpin / CIDR deny → drop, metric reason=target_denied, no Write
     write DATA to selected:port from the associate socket
     inbound origin→client: encapsulate; count toward inbound cap; drop when over
6. Control TCP close / sessionTimeout / idleTimeout (refreshed both ways) → close UDP.
```

Admission: max payload 64 KiB per datagram. Inbound cap 4096 datagrams or `maxInFlightBytes` whichever first, then drop + `Truncated`. We never spoof. We do not claim 1:1 origin packets per client packet.

Capture: one metadata flow `Protocol=socks5`, `SOCKS.Command="udp"`, `intercepted=false`. Do not store every datagram. Last dest + datagram count on `SOCKSInfo`.

Tests live in `internal/proxy/socks_test.go` (two sockets). `proxytest.PlayTranscript` cannot drive the UDP relay — do not use it for ASSOCIATE success. Required: echo associate; domain dest LookupIP once then pin; IMDS datagram dropped; FRAG dropped; inbound flood cap; control-close tears down; `acceptSOCKS5` on + `acceptUDPAssociate` off still `05 07`.

Shutdown `closeBinds` closes live UDP associate sockets so `ReadFrom` unblocks (D42).

See [docs/adr/0012-protocol-expansion-12.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) D59 / D68.

## CONNECT Hijack and inner session

Normative for every `CONNECT` (D19). Tests: two GETs on one CONNECT; “forgot to hijack” must **not** appear as `400` on ClientHello (`testdata/proxy/connect-two-gets.txt`, `connect-hijack.txt`).

```text
1. Handler sees Method == CONNECT.
2. protocols.connect 403 (if disabled) is in ServeHTTP before metrics.accept().
3. serveCONNECT: require host:port (400 still wins). When httpAuth.enabled,
   write 407 via ResponseWriter BEFORE Hijack (contract A; post-accept).
4. Require Hijacker. Hijack() BEFORE writing the body and BEFORE return
   only when proceeding to the tunnel. Never Hijack a 407 CONNECT.
5. Admit + resolve-then-guard on CONNECT host:port (and later SNI).
6. Dial the selected allowed IP:port (no second resolve).
7. Write "HTTP/1.1 200 Connection Established\r\n\r\n" on the hijacked conn.
8. Decide intercept (D20):
   - intercept && hostMatches && port in spec.tls.ports (default {443})
     → tls.Server on client + tls.Client on upstream (internal/tlsmitm).
     Handshake failure → close both, store metadata flow Error=tls_handshake
     or Error=upstream_tls. Do NOT fall back to a blind tunnel.
   - otherwise → bidirectional copy; metadata-only flow (Protocol=connect,
     intercepted=false). No inner HTTP parse.
9. Intercept success: inner HTTP session (HTTP/1.1, or HTTP/2 when enabled).
```

**Inner HTTP (intercepted CONNECT only):**

- One CONNECT = **one** upstream TCP + **one** upstream TLS conn. Do **not** put this conn in the cleartext `Transport` idle pool.
- Handshake ALPN is taken from the session snapshot (D46). Default / flag-off is `http/1.1`. Flag-on advertises `h2` then `http/1.1` on the **leaf**. Origin NextProtos are `["h2","http/1.1"]` only when `protocols.http2.origin` **and** the inner leaf negotiated `h2` (`handshakeOriginNextProtos(spec, innerALPN)`, D64). Inner `http/1.1` never offers origin `h2`. Captured `Protocol` is the **inner client** protocol (D47): `h2` when the leaf negotiated `h2`.
- **HTTP/1.1 inner** (ALPN `http/1.1`, including flag-on when the client did not offer `h2`): serialized `http.ReadRequest` then `Transport.RoundTrip` with a one-shot `DialContext` that returns the already-handshaked upstream `tls.Conn`. Inner `PRI` → close both sides, `Error=http2_inner`. Inner `Upgrade: websocket` + `101` uses the same 101 path as cleartext (copy, or `wsx` pumps when `inspectFrames`). Gate off (`protocols.websocket.enabled` false) → `403` `forbidden` **without** `Connection: close`, `roundTripInner` returns `stop=false`, origin is not invoked. RoundTrip failure writes `502` and closes both TLS sides.
- **HTTP/2 inner** (`protocols.http2.enabled` and leaf ALPN `h2`): `extendedConnect` **off** keeps `http2x.ServeClient` (tun nil). `extendedConnect` **on** must call `http2x.ServeConn` with `PrefaceFull`, `EnableConnectProtocol`, snapshot `maxConcurrentStreams` (0 → 100), and a non-nil `TunnelHandler` — do **not** leave `ServeClient` as the only inner entry point. GET/POST stay on `roundTripInnerH2` (D53). If origin negotiates `h2`, inner streams multiplex on that one CONNECT TCP via `http2x.OriginConn` (refuse-redial; D44 mutex is **not** used; D27 stands). Origin Framer `ENABLE_PUSH=1` only when `protocols.http2.capturePush`; else 0 (D65). Inner SETTINGS `EnablePush` stays 0. `PUSH_PROMISE` is capture-only: promised streams are stored as flows (`HTTP2.Pushed`, `parentStreamId`, `promisedId`) and are **not** forwarded to the inner client. Flag-off RSTs the promised id toward origin immediately. `validateReplay` rejects `Pushed=true`. If origin negotiates `http/1.1` (flag-off or origin has no h2): strip leading-`:` names; hold the origin mutex across `RoundTrip` **and** full body drain so a second stream cannot Dial while `resp.Body` still owns the conn (D44); `MaxConnsPerHost: 1`. Request- and response-phase `WaitPaused` stay **outside** the mutex so a paused stream does not block another stream (D37). h2→h1 request trailers are dropped toward origin, stored on the flow, and counted `labmitm_h2_trailer_dropped_total`. Replay of an h2 flow uses the **live** `protocols.http2.origin` flag (not capture-time): flag-off keeps HTTP/1.1 origin-form with leading-`:` stripped; flag-on offers origin `h2` then `http/1.1` on one Dial. Either HTTPS path closes that one-shot origin TLS conn after the response body is drained (no idle persistConn).
- Inner hop: nested `:method=CONNECT` without `:protocol` is RST_STREAM `PROTOCOL_ERROR`, metric `reason="http2"`, **no flow** (D48 remainder) even when `extendedConnect` is on. Other `:protocol` values RST, no flow. Illegal h2 `Upgrade: websocket` on regular headers RST, no flow. Flag-off (`ServeClient`) still RSTs CONNECT / `:protocol` / Upgrade websocket with no flow.
- Client keep-alive on the inner TLS session is allowed. Each inner request / stream is **one flow**.
- **gRPC decode (D66):** when `protocols.http2.grpcDecode` is on, captured request/response bodies whose content-type is `application/grpc` or `application/grpc+proto` (only) are parsed as gRPC length-prefix + an in-tree protobuf wire tree (`Flow.GRPC`). Max nest depth 8; deeper or bad wire → `DecodeError=malformed`. Short captured bodies → `truncated`. `Message-Encoding` / `grpc-encoding` gzip or deflate stores raw (`Compressed=true`); no decompressor. **grpc-web is opaque** (record content-type, do not parse). Failure is fail-open: the hop still forwards. Flag-off does not set `Flow.GRPC`. Replay uses the raw captured body (the tree is not re-encoded).

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
| **Capture-only** | `rules.enabled: false`, or the winning action is not `body` / `status` / `drop` / `breakpoint` / `redirect` (`silent` / `hang` stay capture-only) | `io.TeeReader` into a buffer capped at `maxBodyBytes`; remainder is copied to the peer with a 64 KiB stack buffer and **not** stored (`Truncated=true`). |
| **Mutating** | Winning action is `body`, `status`, `drop` (before flush), `breakpoint`, or `redirect` | Buffer up to `maxBodyBytes`. Beyond that: fail-closed — skip the `body` replace (`action="body_skipped"`); `status`/`drop`/`breakpoint`/`redirect` still apply to headers. Data-plane continues unmodified for the body. |

`drop` / `status` on the **response** path is illegal after the client has been written any body byte; if the capture-only path already flushed, the action is skipped and counted `action="late_skip"`.

RSS budget:

```
resident            ≤ maxBytes                          # default 256 MiB
reservedInFlight    ≤ maxInFlightBytes                  # default 64 MiB
streamSlack         = 64KiB × maxInFlight               # default 4 MiB
worstRSS            ≈ 256 + 64 + 4 + 64 = 388 MiB
```

## WebSocket / Upgrade (1.0)

`protocols.websocket.enabled` defaults **on** (D22 carve). Disable is fail-closed `403` `forbidden` **before request-phase rules and before any origin RoundTrip / Dial**. Do not strip `Upgrade` and forward as ordinary HTTP. Metric `reason="websocket"`. Captured `Flow.Protocol=websocket`, `Error=forbidden`, `Status=403`.

Cleartext helper `rejectDisabledWebSocket` runs at the **start** of both `serveAbsolute` (proxy `:8888`) **and** `serveOrigDestHTTP` (`:8890` origin-form), after `metrics.accept()`, before `resolveThenGuard`. Inner HTTP/1.1 (`roundTripInner`, CONNECT-pinned `fork()`) writes `403` **without** `Connection: close` and returns `stop=false` so a follow-up GET on the same CONNECT succeeds. Close both TLS sides only if that 403 write fails. Origin is not invoked. Inner h2 Upgrade / Extended CONNECT stay RST (D48); disabled websocket does not add a second h2 path. **1.2 remainder:** `protocols.http2.extendedConnect` `:protocol=websocket` (inner or client-facing h2c) is **not** this 1.0 gate. `protocols.http2.clientCleartext` RFC 9113 CONNECT is **not** `protocols.connect`. Those nested flags stay Reset-only.

If the gate is **on** and the request has `Upgrade: websocket` (case-insensitive) **and** `Connection` contains `Upgrade` (cleartext absolute-form, orig-dest origin-form, **or** an inner request on an intercepted CONNECT):

1. Keep `Upgrade` and rewrite `Connection` to the single token `Upgrade`.
2. Capture request headers (and body if small / capture-only).
3. `RoundTrip` the upgrade.
4. On `101`, set `flow.Protocol = "websocket"`, stop body capture, hijack both legs. Flag-off (`protocols.websocket.inspectFrames` default): insert the flow at 101, then bidirectional copy; do not decode frames. Flag-on (D67): two `internal/wsx` pumps; RSV1–3 are forwarded unchanged; ping/pong forwarded (the proxy does not answer unless the peer sent them); close forwarded then half-close; frames stored on `Flow.WebSocket` under `store.maxBodyBytes` (64-byte overhead + payload each; 4096-frame slice cap). Remainder is forwarded, not stored (`WebSocket.Truncated` and `Flow.Truncated`). Control frames larger than 125 bytes close both sides with `Error=websocket`. A large **data** frame is not a protocol error: the pumps stream the payload and store only the cap. **Insert runs when the inspect session ends** (there is no store update API for live frames); `Wait` / list stay empty for a still-open inspect socket.
5. Response-phase hits on HTTP/1.1 `101` remain `late_skip`. `phase: websocket` may match inspected frames when `inspectFrames` is on ([ADR 0015](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0015-websocket-frame-rules.md) D72–D74). Flag-off stays 101 + copy; websocket-phase items sit in the Engine and never fire. Inner D63 `:status=200` stays response-phase `late_skip`. Client-facing h2c Extended CONNECT has no request-phase or response-phase `matchHit`.
6. Replay of `Protocol=websocket` is rejected. Compat flow REST does not grow a frames array.

If `Upgrade` is present without `Connection: Upgrade`, treat as a normal request.

**HTTP/2 inner Extended CONNECT (D63):** when `protocols.http2.extendedConnect` is on, inner `:method=CONNECT` + `:protocol=websocket` is accepted. SETTINGS `ENABLE_CONNECT_PROTOCOL=1`. If origin negotiated `http/1.1`, the proxy transcodes onto origin HTTP/1.1 `Upgrade: websocket` on the pinned origin TCP. If origin negotiated `h2` (D64), the same CONNECT TCP carries origin RFC 8441 Extended CONNECT (`:protocol=websocket`); no second origin TCP. Success to the inner client is HEADERS `:status=200` (not 101); DATA then carries RFC 6455 frames into the same `wsx` path as HTTP/1.1 101 (`inspectFrames` off = copy; on = capped frames). Other `:protocol` values and nested CONNECT without `:protocol` stay RST, **no flow**. This path does **not** consult `protocols.websocket.enabled` (1.2 nested flag, Reset-only).

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

`sessionTimeout` is an absolute deadline on hijacked CONNECT and WebSocket tunnels (default 10m). `idleTimeout` refreshes on each copied byte on those legs and is also `http.Server.IdleTimeout` on the cleartext hop. `headerTimeout` also bounds the per-conn first-byte peek. `Shutdown` (D42): `accepting=false` → close `rawLn` → close orig-dest listener if bound → wait acceptLoop → close in-peek dispatch conns → closeBinds → wait dispatch goroutines (ctx-bounded; force-close remaining peeks) → `chanListener.Close` → `http.Server.Shutdown` → wait for hijacked sessions up to `--shutdown-timeout`, then force-close them.

Hairpin (D34) compares the pinned IP:port to every live data-plane bind (`s.Addr()`, orig-dest `Addr()`, both spec addresses, and every active SOCKS BIND listen `IP:port` for the lifetime of the control conn) via `sameEndpoint`. Orig-dest **direct-connect**: dest port equals the orig-dest listen port **and** dest IP is local/unspecified → close, no Dial.

## Original-destination listener (1.1, opt-in)

Linux REDIRECT + `SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST` on a separate listener. Dest recover first (no acquire): fail dest / direct-connect / hairpin / CIDR deny → close, no Dial. Peek 1 byte: `0x04`/`0x05` close; `0x16` TLS acquires in dispatch, parses ClientHello (SNI+ALPN) with byte replay, matches `tls.hosts` against **SNI**, Dials dest IP only; else Push `taggedConn` and `ServeHTTP` acquires (D55). Do **not** branch on a single `'P'` (`POST`/`PUT`/`PATCH` share `0x50` with `PRI`).

`ServeHTTP` D57 splice, after PRI and after `gate.acquire`: if orig-dest context is set, `CONNECT` → 400 no Dial; every other method → `serveOrigDestHTTP` (never `serveCONNECT` / `serveAbsolute`). `gate.acquire` once per orig-dest TCP. Flag-on h2c on orig-dest: tagged CONNECT streams are still 400 (D57); regular streams Dial dest IP only.

Ready (D56): `OrigDestBound || OrigDestOff`. 1.0 default is `OrigDestOff: true`. Warning `origdest_unbound` only when required and unbound.

Topologies and iptables: [docs/13-deployment.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/13-deployment.md#original-destination-linux-redirect). Compose: [examples/compose.originaldest.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/compose.originaldest.yaml).

## Client-facing h2c (D61)

Default-off `protocols.http2.clientCleartext` (Reset-only). Requires [ADR 0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) superseding D26's hop list only. **D7 stands.**

| Stream | Behavior |
|---|---|
| Flag-off `PRI * HTTP/2.0` | Hard close before `gate.acquire`. Metric `reason="http2"`. Transcript [testdata/proxy/pri-close.txt](https://github.com/hilather/go-lab-mitmproxy/blob/main/testdata/proxy/pri-close.txt). |
| Flag-on PRI | Hijack, no Write. `http.Server` already consumed `PRI * HTTP/2.0\r\n\r\n`. Leftover is `SM\r\n\r\n` plus SETTINGS in the `bufio.ReadWriter`. `ServeConn` must **not** `ReadFull` the 24-byte preface from the raw conn. Transcript [testdata/proxy/h2c-pri-leftover.txt](https://github.com/hilather/go-lab-mitmproxy/blob/main/testdata/proxy/h2c-pri-leftover.txt) must fail if the preface is re-read from the conn after Hijack. |
| Regular `GET`/`POST` `:scheme=http` `:authority` `:path` | Absolute-form equivalent. Same guards as `serveAbsolute` (including D76 407 when `httpAuth.enabled`). **Allowed** (not CONNECT-only). |
| `:scheme=https` regular | `400` `validation_failed`. Metric `reason="absolute_https"`. |
| `:method=CONNECT` no `:protocol` `:authority=host:port` (RFC 9113 §8.5) | After port parse, when `httpAuth.enabled`: read `Proxy-Authorization` from `Stream.Headers` (`h2cConnectRequest` must copy them) and return `Tunnel{Status:407}` without Dial / AfterAck. Else `resolveThenGuard` + `dialTCP` inside `TunnelHandler`. http2x writes `:status=200` HEADERS first (no HTTP/1.1 200). Then `TunnelRaw` AfterAck → `Server.tunnel` (same `idleTimeout` / `sessionTimeout` as HTTP/1.1 CONNECT) or `TunnelIntercept` AfterAck → `serveInterceptConn` on the framed stream (D62). Handshake failure closes/RST the stream — **no DATA tunnel** (D20). One stream = one origin TCP (D27). WINDOW_UPDATE via `outFlow.take`. Orig-dest tagged CONNECT is `400`, no Dial (D57). Missing port is `400`; no Dial. **Not** `protocols.connect` (that gate is HTTP/1.1 CONNECT on the proxy hop; h2c CONNECT may still 407 while HTTP/1.1 CONNECT 403s). |
| `:method=CONNECT` `:protocol=websocket` | Only if `extendedConnect`. Absolute-form websocket bootstrap then `TunnelWebSocket` AfterAck (D63). Other `:protocol` values RST, no flow. Flag-off RST. **Not** `protocols.websocket` (that gate is HTTP/1.1 `Upgrade: websocket`). |
| Missing `:authority` | `400`; no Dial. |

`http2x.ServeClient` remains the inner ALPN-`h2` wrapper (`PrefaceFull` on the TLS conn). Client-facing CONNECT skips `StreamHandler` and uses `TunnelHandler`. Production Dial stays in `internal/proxy`.

## Related documents

- TLS intercept: [docs/03-tls-interception.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/03-tls-interception.md)
- Store: [docs/04-flow-store.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/04-flow-store.md)
- Rules: [docs/05-rules.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/05-rules.md)
- SOCKS / orig-dest: [docs/adr/0010-socks-and-original-destination.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0010-socks-and-original-destination.md)
- 1.2 BIND / user-pass: [docs/adr/0012-protocol-expansion-12.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md)
- 1.2 h2c: [docs/adr/0012-protocol-expansion-12.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md)

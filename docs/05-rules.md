# Rewrite and Breakpoint Rules

Status: Proposed normative behavior
Owners: Rules, Proxy, Application
Last reviewed: 2026-08-28 (D75 HTTP/1.1 WriteHeader Flush; intercept silent stamp)
Related ADRs: 0002, 0013, 0014, 0015, 0016, 0017

Package `internal/rules`. **Default-off.** Master switch `spec.rules.enabled` must be `true` for any item to fire. First **enabled** item whose match succeeds wins. No weights, no hash-v1, no random (D12).

RULES-001 implements match/eval only. STA-001 compiles `spec.rules` into `snapshot.Rules` (`*rules.Engine`). The proxy loads that Engine once per request / CONNECT so a later live `replaceRules` swap keeps in-flight sessions on the Engine they already matched. Tests may still construct `rules.New(spec)` without the compiler.

Proxy hooks (cleartext absolute-form and intercepted inner HTTP/1.1 **and** inner HTTP/2 streams):

1. After request parse + target guards: request-phase match.
2. After upstream response headers (before any client body byte): response-phase match.
3. Stream vs mutate (D21): capture-only tees to `maxBodyBytes`; `body` / `status` / `drop` / `breakpoint` / `redirect` buffer to `maxBodyBytes` and fail-closed (`body_skipped`) beyond that. `silent` / `hang` / `throttle` are capture-only.
4. Breakpoint: `Insert` paused, `WaitPaused(ctx)` with ctx deadline `min(rule.timeout, store.maxWait)` (1s–60s). Timeout / stale epoch continues unmodified. `Resume` / `Drop` are store primitives (REST in API-001). Unit test Resume without HTTP.

Raw CONNECT tunnels have no inner HTTP, so rules do not apply. Response-phase hits on HTTP/1.1 `101` remain `late_skip`. Inner D63 `:status=200` remains `late_skip`. Client-facing h2c Extended CONNECT has no request-phase or response-phase `matchHit`. `phase: websocket` may match inspected frames when `inspectFrames` is on ([ADR 0015](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0015-websocket-frame-rules.md)). Replay is **not** a rule action (API-001). `action.status: 407` is a **synthetic origin-like response** after DNS on absolute-form / inner HTTP. It is **not** proxy auth (`Proxy-Authenticate` / `replaceHTTPAuth` / D76). Do not invent a `proxyAuth` rule action.

## Schema

```yaml
rules:
  enabled: false
  items:
    - id: break-login          # required, unique, [a-z0-9-]{1,64}
      enabled: true
      phase: request           # request | response | websocket
      match:
        host: "app.lab.test"   # exact, or "*.lab.test"
        pathPrefix: "/login"
        pathExact: ""
        method: POST           # empty = any
        headerName: ""
        headerContains: ""
        protocol: ""           # optional; http/1.1 | h2 | websocket | connect | socks5 | socks4
        opcode: ""             # websocket phase only; continuation | text | binary | close | ping | pong | other
        direction: ""          # websocket phase only; client | origin
        payloadContains: ""    # websocket phase only; unmasked substring
      action:
        type: delay            # breakpoint | drop | delay | status | header | body | silent | hang | redirect | block | throttle (block: websocket only)
        delay: 2s              # delay only; 0–30s
        bytesPerSecond: 8KiB   # throttle only (ignored on delay); 256B–64MiB IEC YAML
        status: 0              # status/drop: empty/0 or 400–599; not the redirect 3xx
        headers:
          set: {}
          remove: []
        body:
          replace: ""          # raw bytes as UTF-8 string in YAML; max 64KiB in spec
        breakpoint:
          timeout: 30s         # 1s–60s
        silent:
          close: rst           # rst | fin; empty → rst
        hang:
          timeout: 5s          # required when type=hang; 1s–30s
          close: rst
        redirect:
          location: "https://app.lab.test/login"  # required when type=redirect
          status: 302          # 301|302|303|307|308; empty → 302
```

Issue [#52](https://github.com/hilather/go-lab-mitmproxy/issues/52) `http_status` is the existing `status` type (no alias). Close-after-status is existing `drop` (default 403). ADR [0014](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0014-qa-block-modes.md) (D69). Frame-phase drop/block is ADR [0015](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0015-websocket-frame-rules.md) (D72–D74).

Match fields are AND. Empty match matches everything (still requires `rules.enabled` and item `enabled`). Host match is case-insensitive. Path match is on the decoded URL path (no query). On an inner HTTP/2 stream the reconstructed request includes ordered pseudo-headers (`:method`, `:scheme`, `:authority`, `:path`); `match.method` uses `:method`, `match.pathPrefix`/`pathExact` use the path-component of `:path` (query stripped), `match.host` uses the host of `:authority`, and `match.headerName` sees leading-`:` names. `match.protocol` is optional and case-insensitive; a non-empty value that does not match the request protocol (including `h2` on an inner h2 stream) matches nothing. Frame-phase eval forces `in.Protocol = websocket`; `match.protocol: websocket` hits, `http/1.1` / `h2` miss. Frame-phase host/path/headers come from the upgrade request snapshot (`splitAuthority` / CONNECT / `origDestCaptureHost`, `requestPath`, `requestCaptureHeaders`) — not `Flow.URL` or `req.Host`. D63 / h2c bootstrap method is `CONNECT`; path is the `:path` pseudo (not implied `/ws`). SOCKS tunnel metadata stamps `Protocol=socks5` or `socks4` (plus `Via`/`SOCKS`). Inner intercept copies the same `Via`/`SOCKS`. Breakpoints pause the **stream**, not the CONNECT TCP session (D37): request-phase `WaitPaused` runs outside the origin mutex so a paused stream does not block another stream’s request-phase rules. The mutex covers origin RoundTrip plus full body drain (D44).

| Action | Request phase | Response phase | Websocket phase |
|---|---|---|---|
| `drop` | Close after optional status (default 403); no upstream | Close after sending nothing more; **illegal in 1.0 if bytes already flushed**. If response headers not yet sent, send `status` or 502. | Omit this frame. Continue the inspect loop (including after a dropped `close`). |
| `block` | `validation_failed` | `validation_failed` | Do not forward the frame. Close both TCP sides. `Error` empty. `State=completed`. |
| `delay` | Sleep then continue | Sleep then continue | `validation_failed` |
| `throttle` | Pace **request** body at `bytesPerSecond`; headers immediate | Pace **response** body at `bytesPerSecond`; headers/status immediate | `validation_failed` |
| `status` | Do not dial; synthesize response with `status` + optional headers/body | Replace status line; headers/body as specified | `validation_failed` |
| `header` | Mutate request headers before dial | Mutate response headers before client write | `validation_failed` |
| `body` | Replace request body (fails closed if truncated / over 64 KiB spec) | Replace response body (same) | `validation_failed` |
| `breakpoint` | Pause before dial; operator resume/edit/drop | Pause after upstream, before client body | `validation_failed` |
| `silent` | No HTTP bytes; TCP RST (default) or FIN. HTTP/2: RST_STREAM `CANCEL` on that stream only | Same; drain and discard origin body. WebSocket `101` is `late_skip` | `validation_failed` |
| `hang` | Hold `hang.timeout` (1s–30s), then silent close. Not resumable | Same after origin headers | `validation_failed` |
| `redirect` | No Dial; synthesize 301/302/303/307/308 (default 302) + required `Location` | Replace status + `Location` | `validation_failed` |

Validate: `rules.items[].id` unique. `action.delay` ∈ [0, 30s]. When `type=throttle`, `action.bytesPerSecond` ∈ [256B, 64MiB]. YAML and REST apply JSON use an IEC string (`8KiB`) via `sizeFields` / `CoerceWireTree`. MCP apply JSON is integer bytes on the typed `RuleActionSpec` (`8192`). Domain `ChangeIn` is `int64`. Other action types ignore `bytesPerSecond`. `action.status` empty or 400–599. Body replace ≤ 64 KiB in YAML. `hang.timeout` required and ∈ [1s, 30s]. `redirect.location` required (≤2048 bytes, no CR/LF/NUL). `redirect.status` empty or 301/302/303/307/308. `silent.close` / `hang.close` empty, `rst`, or `fin`. `http_status` is not a legal type. `phase: websocket` allows only `drop` or `block`. `block` is illegal on `request|response`. `throttle` is illegal on `websocket`. Non-empty `opcode` / `direction` / `payloadContains` on `request|response` is `validation_failed`. Unknown `opcode` or `direction` is `validation_failed`. Websocket-phase items are valid when `inspectFrames` is false.

`payloadContains` compares unmasked bytes. Visibility cap is the pinned full `store.maxBodyBytes` (else 1 MiB), not remaining capture budget. Declared length over that cap is a miss; first-match continues. No message reassembly; `continuation` matches as `continuation` only.

First-match-wins: one item cannot combine `delay` and `throttle`, and `phase: both` stays invalid. Two items are required to pace both directions. `Mutates(throttle)=false` — stay on the capture-only tee path.

Throttle is not a 30s sleep. A 1 MiB body at 256 B/s is about 68 minutes and will hit default `upstreamTimeout` (60s), `idleTimeout` (120s), or `sessionTimeout` (10m). Raise those knobs when a long trickle is the goal: live `replaceAdmission` updates the session gate and pinned deadlines; `http.Server.IdleTimeout` stays Start-time. Concurrent matching requests each get the full configured rate (not a shared connection shaper). WebSocket `101` / Extended CONNECT websocket stay `late_skip` for request/response phase. Raw CONNECT / SOCKS tunnels have no HTTP-body rules. Replay does not evaluate rules.

On the default HTTP/1.1 hop, `writeClientResponse` Flushes after `WriteHeader` when the `ResponseWriter` is an `http.Flusher` so net/http bufio does not hold the status line until the handler returns (D75; issue [#63](https://github.com/hilather/go-lab-mitmproxy/issues/63)). Time-to-first-header is then ≪ body time. Client-facing h2c already sends HEADERS before paced DATA. `writeConnResponse` (intercept HTTP/1.1) writes the status line to the raw conn immediately.

Request-phase `silent` / `hang` on an intercept hop stamp the capture like a completed intercept (`innerFlow`): `intercepted: true`, absolute `https://host[:port]/path` URL, `TLS` filled. Wire RST / RST_STREAM `CANCEL` is unchanged. Cleartext and client-facing h2c stay on `flowFromReq` (`intercepted: false`). Response-phase silent/hang already used `completedFlow`.

## Breakpoint flow

1. `Insert` the flow with `State=paused`, `PausedPhase=request|response` (or `Pause(id)`).
2. Store `Subscribe` emits `paused`; REST SSE and MCP `subscriptions/listen` adapt that hook.
3. Proxy session `WaitPaused(ctx, id)` with ctx deadline = rule timeout (1s–60s, cap `store.maxWait`).
4. `POST /v1/flows/{id}:resume` → `store.Resume` (optional header/body patch, same caps).
5. `POST /v1/flows/{id}:drop` → `store.Drop` (client gets 502 if headers not sent).
6. Timeout / `ErrStaleEpoch` → re-lookup the row; if still paused, `ExpireBreakpoint` (completed, `Error=breakpoint_timeout`) so a late Resume is `ErrBreakpointInactive`; continue unmodified (do not hang the SUT). Metric `labmitm_rule_hits_total{action="breakpoint_timeout"}`. Audit `flow.breakpoint_timeout` is OBS-001 (not emitted yet).

PR 6 unit test (`internal/rules` + store): `Insert` paused → goroutine `WaitPaused` → `Resume` with patch → assert patch and `State=open` (request-phase) without opening a socket. Compile of YAML → rule index is STA-001 only; RULES-001 uses a test-constructed `model.RulesSpec`.

## Replay

Replay is **not** a rule action. `POST /v1/flows/{id}:replay` calls `proxy.Replay(stored *Flow)`:

- Builds HTTP/1.1 origin-form from the stored request (`scheme`, `host`, `method`, `path`, headers, body). Leading-`:` pseudo-header names are stripped; `Host` comes from `:authority` when present (else `Flow.Host`). This is not “replay the h2 session.”
- Dials the **origin** via the same resolve-then-guard + `DialContext` path as live traffic. Authority is `Flow.Host` when it already includes a port; when `Host` is hostname-only (intercept `innerFlow` / cleartext `flowFromReq`), host:port comes from the captured URL so `https://127.0.0.1:18443/ok` Dials `:18443`, not `:443`. Scheme defaults (`https`→443 / `http`→80) apply only when the URL also omits a port.
- If `scheme=https`, `tls.Client` on that dial using the current snapshot’s upstream verify knobs. Does **not** require `tls.intercept` to be on — replay is an operator-originated origin fetch, not a client CONNECT. The one-shot HTTPS hop (HTTP/1.1 Transport or live-origin `NewOriginTransport`) closes the TLS conn when the caller finishes the response body (no idle persistConn leak). HTTP/1.1 uses `DisableKeepAlives`.
- `Transport.Proxy = nil`. `HTTP_PROXY=http://127.0.0.1:8888` must not change the dial.
- Never dial `listeners.proxy.address` (hairpin reject even if that address is loopback).
- New flow id (`Protocol=http/1.1`). Requires `mitm.write`.
- Reject `Protocol=websocket|connect`, CONNECT-metadata-only flows, and flows with `Request.Truncated` (`validation_failed`). Captured `Protocol=h2` is replayable.

Tests: HTTP replay; HTTPS replay with intercept both on and off; HTTPS replay releases the origin conn (HTTP/1.1 and live-origin h2); Host-without-port + URL-with-port Dials the URL port (HTTP and HTTPS); `HTTP_PROXY` ignored; hairpin address rejected; h2 flow replay is HTTP/1.1 origin-form without `:method` unless live `protocols.http2.origin` is on.

Live apply `replaceRules` compiles a new snapshot; in-flight requests keep the old snapshot. Websocket-phase eval uses that same STA-001 pin: next cleartext / orig-dest HTTP Upgrade, next CONNECT (inner Upgrade and inner D63), next h2c PRI. Open inspect sockets never reload. `inspectFrames` stays Reset-only (D51' / D74).

## Related documents

- Stream vs mutate: [docs/02-proxy-semantics.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md)
- Store breakpoint primitives: [docs/04-flow-store.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/04-flow-store.md)
- Plan/apply `replaceRules`: [docs/06-state-and-configuration.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/06-state-and-configuration.md)

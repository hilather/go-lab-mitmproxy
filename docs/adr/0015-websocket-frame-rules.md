# ADR 0015: WebSocket frame rules (D72–D74)

Status: Accepted
Date: 2026-08-28
Decisions: D72, D73, D74

## Context

[ADR 0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) **D67** added default-off `protocols.websocket.inspectFrames`. Flag-off stays HTTP/1.1 `101` + bidirectional copy. Flag-on decodes RFC 6455 frames in the shared `internal/wsx` pump (`inspectUpgrade`). Inner Extended CONNECT (D63) reuses that pump; success is `:status=200`.

[docs/02-proxy-semantics.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md) and [docs/05-rules.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/05-rules.md) said mutating rules do **not** apply after `101` / that mutating **response** rules after a WebSocket `101` are `late_skip`. That was the only post-101 rule story. Request-phase on the Upgrade request already runs. Client-facing h2c Extended CONNECT never calls response-phase `matchHit`.

[ADR 0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md) **D51'** keeps `inspectFrames` Reset-only. `setFeature` of that ID is `validation_failed`. `replaceRules` and `setFeature rules.enabled` are already live. Catalog is 31 `/v1` rows. STA-001 pins the Engine once per request (cleartext / orig-dest HTTP), once per CONNECT (inner), or once per h2c PRI — not per inner upgrade and not per h2c stream.

Issue #52 asked for post-101 WebSocket frame **drop** (omit one frame) and **block** (close both TCP sides), live via existing REST/MCP `replaceRules`. Reusing `phase: response` would break empty-match response `drop` / `delay` / `breakpoint` (today: 101 + copy + `late_skip`).

This ADR **does not supersede** D7, D12, D19, D20, D21, D51', or D67. It **does supersede** the two sentences above as the *only* post-101 story (not `late_skip` itself).

## Decision

### D72 — New rule phase `websocket` (per inspected frame after 101)

`model.RulePhaseWebSocket = "websocket"`. `KnownRulePhase` is `request | response | websocket`.

Eval hook: only inside `wsInspect.pump` after `wsx.ReadHeader` (and after reading as much payload as match needs). Not on the flag-off copy path. Not on response-phase at 101. Flag-off illegal h2 `Upgrade: websocket` stays RST, no flow (D48).

First enabled AND-match wins **per frame**, independently of any request/response hit on the upgrade. Empty match matches every frame on that socket (still requires `rules.enabled` and item `enabled`). Linear scan continues after a predicate miss (including an oversized `payloadContains` miss).

Match input is a pre-pump snapshot of the upgrade request (`host` already used for request-phase `matchHit` where that exists; `splitAuthority` host on h2c; `requestPath` / `requestMethod` / `requestCaptureHeaders`). Do **not** read `req.Host`, `Flow.URL`, or `Flow.Request.Headers`. Force `in.Protocol = websocket` at eval. Do **not** reuse `matchHit` (it sets `requestProtocol`). Do **not** add h2c `matchHit`. Do **not** `beginSession` inside `inspectUpgrade`.

Additive match fields on the shared `RuleMatchSpec`: `opcode` (exact `continuation` \| `text` \| `binary` \| `close` \| `ping` \| `pong` \| `other`), `direction` (`client` \| `origin`), `payloadContains` (unmasked substring; empty is any; non-empty + `Payload == nil` is always a miss). Visibility cap is the **full** pinned `store.maxBodyBytes` (else `defaultMaxBodyBytes`), not `storeRemain()`. Declared length over that cap is a fail-open miss; first-match continues. No regex. No message reassembly.

`phase: websocket` allows only `action.type` `drop` or `block`. `block` is illegal on `request|response`. Non-empty frame fields on `request|response` are `validation_failed`. Websocket items are valid when `inspectFrames` is false; they never fire on the copy path.

### D73 — Frame actions `drop` and `block`

| Action | `phase: websocket` | Wire |
|---|---|---|
| `drop` | Omit this frame. Continue the inspect loop (including after a dropped `close`). | Peer never sees the header or payload. |
| `block` | Do not forward the frame. Close both TCP sides. | Session ends. `Error` stays empty. `State=completed`. |

Close-length-1 (`OpcodeClose && Length==1`) is a header fact. On the rules path, call today’s `protocolError()` immediately after `ReadHeader`. No `Match`. No `WriteHeader`. No drop/block. Fast path may keep today’s forward-then-error order.

`labmitm_rule_hits_total{action="drop"|"block"}` uses the same series as HTTP (no `phase` label). `labmitm_ws_frames_total` stays frames **forwarded** — increment only on the miss/forward path via today’s `captureFrame`. Drop/block use a no-`wsFrame` sibling (same `FrameCount` / no-append / clip / `st.stored` / `Truncated`). GET-by-id `frames[].action` (`""` omitempty = forwarded). `Flow.RuleIDs` appends the websocket-phase id under `wsInspect.mu`. Do not hold that lock across capture.

Miss-forward after a match-time payload read writes the original **wire** bytes (or remasks a copy). Do not `TeePayload` a consumed `src`. Do not write the unmasked buffer. Do not consume `src` on an oversized miss. Drop/block unread is one `TeePayload(io.Discard, n=h.Length, storeMax=storeRemain())`.

### D74 — Live `replaceRules`; `inspectFrames` remains Reset-only

`inspectFrames` stays D51' / D67: bootstrap YAML + Reset (wipes flows). `setFeature` of that ID stays `validation_failed`.

Rule items use existing `replaceRules`. `setFeature rules.enabled` flips only the master switch and is subject to the same pin:

| Entry | When Engine is loaded | What sees `replaceRules` / `setFeature rules.enabled` |
|---|---|---|
| Cleartext absolute-form / orig-dest HTTP Upgrade | `beginSession` of that request | the **next** such request |
| Inner HTTP/1.1 Upgrade, inner Extended CONNECT | CONNECT / SOCKS CONNECT / orig-dest TLS pin (`fork` copies `eng`) | the **next CONNECT**, not a later inner upgrade on the same CONNECT |
| Client-facing h2c Extended CONNECT | PRI / `serveH2C` | the **next h2c TCP**, not a later stream on the same PRI |
| Open inspect socket | already pinned | never |

Catalog stays 31 rows. No new capability IDs. Domain logic stays in `internal/rules` + `internal/proxy` (`wsInspect.pump`). Hook once in the shared pump so D63 inherits automatically. Do not add an h2-specific rule table. Do not add h2c request-phase or response-phase `matchHit`.

## Consequences

- Operators Reset once with `inspectFrames: true`, then live `replaceRules` for which frames drop/block on sessions that have not yet pinned an Engine.
- HTTP/1.1 `101` and inner D63 `:status=200` response-phase hits remain `late_skip`.
- Client-facing h2c Extended CONNECT still has no HTTP request/response rule eval; frame-phase still runs when inspect is on.
- Canonical JSON of any non-empty `rules.items` list grows three empty match keys (`opcode`, `direction`, `payloadContains`).
- D7, D12, D16, D19, D20, D21 stand. No Dial idents outside `internal/proxy`.

## Alternatives considered

- Reuse `phase: response` + `match.protocol: websocket` after 101: rejected. Breaks empty-match response `drop` / `delay` / `breakpoint`.
- Make `inspectFrames` live (`setFeature`): rejected. D51' review trigger; cannot switch a live 101-copy socket onto `wsx` mid-stream.
- Per-frame Engine reload: rejected. Violates STA-001.
- New capability / `POST /v1/ws-rules`: rejected. Catalog stays 31. Adapters stay adapters.
- Payload regex / message reassembly: rejected (D12 and extra state machine).
- New HTTP/2 WebSocket match surface: rejected. D63 already shares `wsx`.
- Miss-forward via `TeePayload(src)` after a match read: rejected. Consumed `src` writes a header with no payload.
- Treat `payloadContains` as skipped when `Payload==nil`: rejected. Oversized first-match would swallow a large data frame.

## Review triggers

Review when live `inspectFrames` is proposed, when per-upgrade Engine reload is proposed, when frame `delay` / body-replace / breakpoint is proposed, or when a new HTTP/2 WebSocket match table is requested.

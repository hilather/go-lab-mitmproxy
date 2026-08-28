# Plan: Post-101 WebSocket frame rules (block/drop)

Status: In review (plan only — not implemented)
Owners: Rules, Proxy, Application
Last reviewed: 2026-08-28
Issue: [#52](https://github.com/hilather/go-lab-mitmproxy/issues/52) item “Post-101 WebSocket frame rules (block/drop mid-stream). Live configurable via MCP/REST.”
Supersedes: [PR #56](https://github.com/hilather/go-lab-mitmproxy/pull/56) (blocked after 3 skeptic sweeps). Do not implement from that revision.
Related ADRs: [0002](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0002-in-tree-http-forward-proxy.md), [0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) D67, [0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md) D51'
This plan: **ADR 0015** required (see numbering below)

This file is a planning contract. It does not change product behavior. Implementation is a later change that must land ADR, code, tests, and numbered-pack edits together.

## ADR / decision numbering (collision)

On `main`, [ADR 0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md) is already D51'. The previous websocket plan ([PR #56](https://github.com/hilather/go-lab-mitmproxy/pull/56)) claimed ADR 0014 / D69–D71.

In-flight #52 plans collide with those numbers:

| Plan | PR | Claims |
|---|---|---|
| Bandwidth throttle | [#54](https://github.com/hilather/go-lab-mitmproxy/pull/54) | ADR **0013** / D69 |
| HTTP 407 proxy auth | [#55](https://github.com/hilather/go-lab-mitmproxy/pull/55) | ADR **0014** / D69 |
| QA block modes | [#53](https://github.com/hilather/go-lab-mitmproxy/pull/53) | ADR **0013** / D69 |

This work therefore writes **ADR 0015** and decisions **D72**, **D73**, **D74**. Do not reuse 0013, 0014, or D69–D71.

## Goal

Smallest correct change so an operator can, after a WebSocket `101` (or inner D63 `:status=200` + RFC 6455 DATA), match inspected frames and **drop** (omit one frame) or **block** (close both TCP sides) mid-stream. Configuration is the existing `spec.rules` subtree, applied live through REST/MCP `replaceRules`. Do not invent a new HTTP/2 WebSocket surface. Do not add a chaos engine (D12).

## Current behavior (must not be silently rewritten)

Cited, not invented:

- [docs/05-rules.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/05-rules.md): phases are `request` | `response`. First enabled AND-match wins. `replaceRules` compiles a new snapshot; in-flight sessions keep the Engine they already loaded. **Mutating response rules after a WebSocket `101` are `late_skip`.** That sentence is today’s *only* post-101 rule story.
- [docs/02-proxy-semantics.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md): “Mutating rules do **not** apply after `101`.” Flag-off `inspectFrames` inserts then bidirectional-copies (no decode). Flag-on (D67) runs two `internal/wsx` pumps in `inspectUpgrade`. Insert of an inspect session happens when the socket ends. Response `drop`/`status` after any client body byte is `late_skip`.
- `internal/proxy/forward.go` / `intercept.go`: **any** response-phase hit on HTTP/1.1 `101` increments `late_skip` and the action is not applied. Inner D63 (`innerH2Tunnel`) counts `late_skip` on `:status=200` and does **not** send that 200 through `finishResponseWrite`. Client-facing h2c (`h2cWebSocketTunnel`) **never** calls response-phase `matchHit`. `TestWebSocketLateSkip` covers `body` only.
- `matchHit` takes `host` as a **caller argument** (`splitAuthority` / CONNECT host), not `req.Host` (often `host:port`). It passes `requestProtocol(req)`: cleartext / inner HTTP/1.1 Upgrade is `http/1.1`. After 101 the flow is stamped `Protocol=websocket`, but request-phase match still saw `http/1.1`. D63 / h2c Extended CONNECT sets `h2Meta.protocol = websocket` and method `CONNECT`; path is `:path`, not automatically `/ws`.
- `inspectUpgrade(client, leftover, upstream, fromUp, sess, f)` receives `*ruleSession` but **does not store it**. `wsInspect` today is `{s, f, max, ad, client, upstream, mu, stored, stopCap}`. There is no `st.sess`.
- Cleartext `flowFromReq` sets `Method`, `Host`, and `URL = req.URL.String()` and does **not** set `Request.Headers`. `Flow.URL` is `http://host/ws`, not `requestPath` (`/ws`). Only `innerFlow` stamps `requestCaptureHeaders`.
- Today’s inspect pump (`wsInspect.pump`): `ReadHeader` → **immediate** `WriteHeader` → `TeePayload(dst, src, …)` (copies **wire** bytes; masking unchanged; returns unmasked store prefix) → close-length-1 `protocolError` → `captureFrame`. A large data frame is streamed, not buffered. `labmitm_ws_frames_total` is incremented in `captureFrame` (help text: frames **forwarded**).
- [ADR 0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md) **D51'**: `protocols.websocket.inspectFrames` is a **1.2 nested flag and stays Reset-only**. `setFeature` of that ID is `validation_failed`. `protocols.websocket.enabled` is a different, live hop gate (403 before rules/Dial; default on). ADR 0013 rejected “rules-only QA after 101” as the *primary hop gate*; that does not forbid a later frame-phase once inspect exists.
- STA-001 / ADR 0013 pin: Engine is loaded once per **request** (cleartext / orig-dest HTTP) or once per **CONNECT** (inner `pinned.fork()`) or once per **h2c PRI** (`serveH2C`; later streams reuse that pointer). Not per inner upgrade and not per h2c stream.
- Catalog is **31** `/v1` rows (`features.get`). No new capability IDs.
- `testdata/proxy/upgrade-websocket-frames.txt` covers 101 + inspect handshake. Frame bytes are driven in `internal/proxy/ws_test.go`. Existing D63 tests are handshake + echo, not inspect+rules.
- Illegal h2 `Upgrade: websocket` stays RST, **no flow** (D48 remainder).

## Non-goals

- HTTP block modes (`http_status`, `hang_until_timeout`, redirect, RST vs close) — other #52 item.
- Bandwidth throttle / per-frame `delay` — other #52 item.
- Live `inspectFrames` / `setFeature` of 1.2 nested flags (D51' stands).
- Per-frame or per-upgrade Engine reload (STA-001 stands).
- New capability IDs, new plan/apply verbs, `replaceProtocols`, `POST /v1/features/{id}`.
- New HTTP/2 WebSocket protocol, new `:protocol` values, or changing D48 / D63.
- Adding response-phase `matchHit` on client-facing h2c.
- Frame reassembly (continuation → message). Per-frame only.
- Regex, weights, hash, random (D12).
- Breakpoint / resume / body-replace / status / header mutate on frames.
- Compat flow REST frames array (still omitted).
- Replay of `Protocol=websocket` (still rejected).
- UI Frames-tab chrome (optional follow-on).
- Making `inspectFrames` default on. Empty `spec: {}` stays 101-copy.
- New `labmitm_rule_hits_total` label (`phase`). Websocket `drop` reuses `{action="drop"}`.
- Schema `if`/`then` for action-vs-phase (Go `validateRules` is fail-closed).

## Why an ADR is required

Two invariants change together:

1. **`late_skip` is no longer the only post-101 rule story.** Every `phase: request|response` action on an HTTP/1.1 `101` stays `late_skip`. Inner D63 `:status=200` stays today’s response-phase `late_skip`. A new phase evaluates *after* 101 / inner 200 on decoded frames. Reusing `phase: response` would break empty-match response `drop` **and** `delay`/`breakpoint` (today: 101 + copy + `late_skip`).
2. **Frame decode is gated by Reset-only `inspectFrames` (D51' / D67).** Live `replaceRules` can change *which* frames drop/block on sessions that have not yet pinned an Engine. It cannot turn decode on.

ADR **0015** **does not supersede** D7, D12, D19, D20, D21, D51', D67. It **does supersede** these two sentences as the *only* post-101 story (not `late_skip` itself):

- docs/02: “Mutating rules do **not** apply after `101`.”
- docs/05: “Mutating response rules after a WebSocket `101` are `late_skip`.”

Replacement (frozen):

- Response-phase hits on HTTP/1.1 `101` remain `late_skip`.
- Inner D63 `:status=200` remains `late_skip` (already counted in `innerH2Tunnel`; do not send that 200 through `finishResponseWrite`).
- Client-facing h2c Extended CONNECT **stays “no response-phase eval.”** Do **not** add `matchHit` on `h2cWebSocketTunnel` to manufacture a `late_skip`.
- `phase: websocket` may match inspected frames when `inspectFrames` is on.

## Proposed ADR 0015 (write in the implementation change)

Working title: `docs/adr/0015-websocket-frame-rules.md`. Decisions **D72**, **D73**, **D74**.

### D72 — New rule phase `websocket` (per inspected frame after 101)

`model.RulePhaseWebSocket = "websocket"`. `KnownRulePhase` becomes `request | response | websocket`.

Eval hook: only inside `wsInspect.pump` after `wsx.ReadHeader` (and after reading as much payload as match needs — see **Pump I/O**). Not on the flag-off copy path. Not on response-phase at 101. Flag-off illegal h2 `Upgrade: websocket` stays RST, no flow (D48).

First enabled AND-match wins **per frame**, independently of any request/response hit on the upgrade. Empty match matches every frame on that socket (still requires `rules.enabled` and item `enabled`). Linear scan continues after a predicate miss (including an oversized `payloadContains` miss).

#### Match snapshot (not `*Flow`)

`inspectUpgrade` / `wsInspect` today do **not** hold `*ruleSession`. Implementation must **add** the pinned sess/engine **and** a request snapshot; do not hunt for `st.sess`.

**Snapshot once before the pumps.** Callers already have the same `host` string they pass into request-phase `matchHit` (`hijackUpgrade`, inner HTTP/1.1, `innerH2Tunnel`, `h2cWebSocketTunnel`). Pass that `host` plus the upgrade `*http.Request` into `inspectUpgrade` (signature change is an implementation detail). Snapshot:

| Field | Source |
|---|---|
| Host | The same `host` string already passed into request-phase `matchHit` (`splitAuthority` / CONNECT host). **Not** `req.Host` (often `host:port`). `Flow.Host` happens to be that string; still do not read match input from `*Flow`. |
| Path | `requestPath(req)` |
| Method | `requestMethod(req)` |
| Headers | `requestCaptureHeaders(req)` (already merges h2 `:authority` / `:path` / `:method` / other pseudos) |

Force `in.Protocol = websocket` at eval. Do **not** reuse `matchHit` (it sets `requestProtocol`). Do **not** use `Flow.URL` as path. Do **not** use `Flow.Request.Headers` on `flowFromReq` paths.

| Input | Source |
|---|---|
| Host, path, method, headers | Pre-pump snapshot above |
| `in.Protocol` | Always the token `websocket` for this phase. Empty `match.protocol` matches; `websocket` matches; any other non-empty token (`http/1.1`, `h2`, …) matches nothing |
| Opcode, direction, payload | The frame being inspected |

D63 / client-facing h2c bootstrap: `Method` is `CONNECT`; path is the `:path` pseudo (not implied `/ws`). Operators who write `pathPrefix: /ws` must use that path on the Extended CONNECT request. Document this; do not invent a second match table.

`matchAND` already prefers `:authority` / `:path` / `:method` when those headers are present. Snapshotting via `requestCaptureHeaders` keeps frame-phase host/path/method aligned with request-phase on D63 / h2c.

#### Additive match fields

AND, all optional. They live on the shared `RuleMatchSpec` (JSON Schema `additionalProperties: false` requires listing them):

| Field | Tokens / rule | Notes |
|---|---|---|
| `opcode` | empty = any; else exact `continuation` \| `text` \| `binary` \| `close` \| `ping` \| `pong` \| `other` | Same tokens as `wsx.OpcodeName` / `labmitm_ws_frames_total`. Unknown YAML value is `validation_failed`. No regex. |
| `direction` | empty = any; else `client` \| `origin` | Existing `WSDirection*` tokens. Unknown YAML value is `validation_failed`. |
| `payloadContains` | empty = any; else substring of the **unmasked** payload | YAML string compared as raw bytes (`bytes.Contains`, UTF-8 of the YAML value). No regex. |

`store.maxBodyBytes` pinned on the inspect session is reused as the **payloadContains visibility cap**, not as a new knob:

- Visibility cap is the **full** pinned value already used as `wsInspect.max` (`maxBodyOf(sess)`: spec `store.maxBodyBytes` if > 0, else the existing `defaultMaxBodyBytes` `1<<20`). **Not** `storeRemain()` (remaining capture budget). A later frame whose declared length is still ≤ the full cap may content-match even if earlier frames already filled the store.
- If declared frame length **exceeds** that full pinned cap, `payloadContains` is a **miss** (fail-**open** for that predicate). First-match **continues**; a later opcode/direction-only item may still win.
- Residual: content-match cannot see frames larger than the pinned capture cap. `replaceStoreCaps` does not change an already-pinned inspect socket.

No message reassembly. A `continuation` frame is matched as opcode `continuation` only.

Validate (Go `validateRules`, fail-closed; JSON Schema widens enums only — no new `if`/`then`):

- `phase: websocket` allows **only** `action.type` `drop` or `block`. `delay`, `status`, `header`, `body`, `breakpoint` on this phase are `validation_failed`.
- `phase: request|response` plus `action.type: block` is `validation_failed`.
- `opcode` / `direction` / `payloadContains` **non-empty** on `phase: request|response` is `validation_failed`.
- Unknown `opcode` or `direction` is `validation_failed`.

`phase: websocket` items are **valid when `inspectFrames` is false**. They sit in the Engine and never fire on the copy path. No inspectFrames cross-field validate. Prerequisite: Reset once with `inspectFrames: true`, then live `replaceRules`.

Canonical JSON: `RuleMatchSpec` has no `omitempty`. Adding the three fields inserts empty keys on **every existing** `rules.items[]` entry. Empty `spec: {}` revision can stay stable (`items: []`). There are **no** revision goldens today (`TestConfigCompat` round-trips). Changelog must note canonical-JSON churn for non-empty `items[]`.

Engine stays pure (no I/O). Extend `rules.Request` with `Opcode`, `Direction`, `Payload []byte`. `Match("websocket", …)` is first-match. A small Engine helper (name is an implementation detail) answers “must the pump load payload before `Match`?” by walking enabled websocket-phase items in order:

1. If non-payload AND fields miss → continue.
2. If `payloadContains` is empty → this item would win without a load → **do not load**.
3. If declared length **exceeds** the visibility cap → this item misses → continue.
4. Otherwise this item needs unmasked bytes → **load**.

The pump then optionally loads and calls `Match` once. Do not put `io.Reader` in `internal/rules`.

### D73 — Frame actions `drop` and `block`

Phase-dependent `drop` (HTTP request/response `drop` unchanged):

| Action | `phase: websocket` | Wire |
|---|---|---|
| `drop` | Omit this frame. If `src` is still unread, drain (`io.CopyN` to `Discard`, never `TeePayload` onto `dst`) so the stream stays aligned. Continue the inspect loop (including after a dropped `close`). | Peer never sees the header or payload. |
| `block` | Do not forward the frame. Close both TCP sides. | Session ends. |

`block` is a new `KnownRuleAction` token, legal **only** on `phase: websocket` in this change.

**Close vs `protocolError` (frozen):**

- `block` closes both conns **without** setting `Error=websocket`. `Flow.State` stays `completed` (today `flowFromReq` already stamps `completed` before inspect). No new Error token.
- D67 protocol errors stay D67: `ReadHeader` still rejects control >125 as `ErrProtocol` → `protocolError` (`Error=websocket`, `State=error`) **before** rule eval. Close with payload length 1 is detected after the payload is available; if that frame was a `drop` or `block` candidate, still `protocolError` (`Error=websocket`) — rules do not swallow a framing violation.
- The peer pump today only early-exits when `f.Error == WSErrorProtocol`. `block` must `Close` both conns so the other pump unblocks on read/write error. Do not set `WSErrorProtocol` for `block`.

Metrics:

- `labmitm_rule_hits_total{action="drop"|"block"}` on a websocket-phase hit. **Same series as HTTP** — no new `phase` label. Document `block` as a new `action` token in `docs/11-observability.md`.
- `labmitm_ws_frames_total` stays “frames **forwarded**.” Increment it only on the miss/forward path. `drop` / `block` increment `rule_hits` only. Do not count omitted frames as forwarded.
- Response-phase `late_skip` on 101 / inner 200 is unchanged. Do not count the skipped HTTP action as a frame hit.

Capture: still store the inspected frame under existing caps (including dropped/blocked frames, with `Action` set). Additive `WebSocketFrame.Action` (`""` forwarded, `"drop"`, `"block"`).

**GET-by-id JSON (frozen):** field name `action` on each frame object (`""` omitempty = forwarded; `drop` / `block` present). List still omits `frames` (docs/04). Compat does not grow a frames array. Both REST and MCP DTOs (`fromWebSocket` and the MCP equivalent) **must** map `Action`; add/extend `TestContractWebSocketFrames` in both adapters.

**`Flow.RuleIDs`:** a websocket-phase hit **appends** the rule id (same slice HTTP request/response hits already use). Inspect capture today calls `capture(f, sess)` not `captureRule`; the implementation change must stamp `RuleIDs` on a websocket-phase hit before insert.

**`RuleIDs` / `Action` writes** go under `wsInspect.mu` (docs/04: do not unsynchronized-mutate a live `*Flow`). Two pumps eval concurrently.

RSV bits, ping/pong auto-answer policy, control-size `Error=websocket`, and large-data streaming on **non-matching** / opcode-only frames stay as D67.

### D74 — Live `replaceRules`; `inspectFrames` remains Reset-only

- **`inspectFrames`:** D51' / D67 stand. Bootstrap YAML + Reset (wipes flows). `setFeature` of this ID stays `validation_failed`.
- **Rule items:** existing `replaceRules` (REST `POST /v1/changes:apply`, MCP `mitm_change_apply`). `setFeature` `rules.enabled` flips only the master switch and is subject to the **same pin** as `replaceRules` (it cannot disarm an open inspect socket or a later inner upgrade on a pinned CONNECT / PRI).
- **Pin (STA-001 / ADR 0013, not “next upgrade”):**

| Entry | When Engine is loaded | What sees `replaceRules` / `setFeature rules.enabled` |
|---|---|---|
| Cleartext absolute-form / orig-dest HTTP Upgrade | `beginSession` of that request | the **next** such request |
| Inner HTTP/1.1 Upgrade, inner Extended CONNECT | CONNECT / SOCKS CONNECT / orig-dest TLS pin (`fork` copies `eng`) | the **next CONNECT**, not a later inner upgrade on the same CONNECT |
| Client-facing h2c Extended CONNECT | PRI / `serveH2C` | the **next h2c TCP**, not a later stream on the same PRI |
| Open inspect socket | already pinned | never |

Do not add per-frame or per-101 reload. Plan of `replaceRules` does not need a new warning token.

- **Catalog:** stays 31 rows. Adapters stay adapters. Domain logic in `internal/rules` + `internal/proxy` (`wsInspect.pump`). No Dial idents outside `internal/proxy`.

Hook once in the shared pump so D63 Extended CONNECT inherits automatically. Do not add an h2-specific rule table. Do not treat illegal h2 `Upgrade: websocket` as a frame-rule opportunity (still RST, no flow). Do not add h2c response-phase `matchHit`.

## Pump I/O contract (the #56 unblock; part of D72)

This is the sweep-3 blocker from [PR #56](https://github.com/hilather/go-lab-mitmproxy/pull/56). After a match-time payload read, `src` is consumed. “Miss → existing `WriteHeader` + `TeePayload(src)`” then writes a header with no payload. Writing the unmasked match buffer would unmask client→origin frames (D67: `TeePayload` copies **wire** bytes; masking unchanged). An oversized miss that drains `src` with no later winner swallows a large data frame instead of streaming it.

Frozen algorithm for `wsInspect.pump` after a successful `ReadHeader`:

### Fast path (D67 unchanged)

If the pinned Engine is nil, `rules.enabled` is false, or it has **no** enabled `phase: websocket` item: today’s path. `WriteHeader` then `TeePayload(src)`. Do not buffer. Close-length-1 and `captureFrame` stay as they are (this path forwards, so `ws_frames_total` still increments inside `captureFrame`).

### Rules path

**Do not `WriteHeader` until the winner is known.** A premature header makes `drop` impossible.

State on this frame:

- `srcConsumed` starts false.
- `wire` is the exact payload bytes read from `src` (masked if the header said masked).
- `unmasked` is a copy of `wire` with `MaskKey` applied when `h.Masked` (match + capture only).

**Load rule:** run the Engine helper above. Load **only** if it says the first still-viable item needs `payloadContains` **and** declared length ≤ visibility cap.

**On load (≤cap):** `io.ReadFull(src, declared)` into `wire`. Set `srcConsumed=true`. Build `unmasked` from a copy. Do **not** write anything yet. Do **not** consume `src` on an oversized `payloadContains` miss — that predicate misses; payload stays on `src` until the winner is known.

**Then** `Match("websocket", snapshot + Protocol=websocket + opcode + direction + Payload=unmasked-or-nil)`.

**Close-length-1** (and any other D67 post-payload framing check): if the payload is available (`srcConsumed` or declared length 0) and `OpcodeClose && Length==1` → `protocolError` and return, **even if** a rule would have dropped or blocked.

Then:

| Winner | `src` | `dst` | Capture / metrics |
|---|---|---|---|
| `drop` | If not consumed, drain to `Discard` (alignment only). | **No** `WriteHeader`. **No** payload write. | Store frame with `Action=drop`; append `RuleIDs` under `mu`; `rule_hits{action="drop"}`; **no** `ws_frames_total`. Continue the loop (including after a dropped `close`). |
| `block` | Same drain-if-unread. | **No** `WriteHeader`. `Close` both conns. | Store frame with `Action=block`; append `RuleIDs` under `mu`; `rule_hits{action="block"}`; **no** `ws_frames_total`. `State=completed`. Return. |
| none (miss), `src` still unread | still on `src` | `WriteHeader` + `TeePayload(src)` (streams large data; masking unchanged) | Existing `captureFrame` path (`ws_frames_total` increments). |
| none (miss), `src` already consumed | n/a | `WriteHeader` + write **`wire`** (original mask). Allowed equivalent: re-mask `unmasked` with the **same** `MaskKey` and write those bytes. **Forbidden:** `TeePayload` of a consumed `src`; writing `unmasked` on a masked client→origin frame; `wsx.WriteFrame` with a truncated prefix (would lie about `Length`). | Capture the unmasked prefix under `storeRemain()` (same cap as `TeePayload`’s `storeMax`). Increment `ws_frames_total`. |

`io.ReadFull` / write errors end the pump the same way today’s `TeePayload` errors do (not `Error=websocket` unless `ErrProtocol`).

Do **not** invent a second HTTP/2 WebSocket pump. Both directions of the shared `wsInspect.pump` share this.

## Why not smaller alternatives

| Alternative | Why rejected |
|---|---|
| Reuse `phase: response` + `match.protocol: websocket` after 101 | Breaks empty-match response `drop` / `delay` / `breakpoint` (today `late_skip` + working 101). |
| Make `inspectFrames` live (`setFeature`) | D51' review trigger; cannot switch a live 101-copy socket onto `wsx` mid-stream. Residual: Reset once to enable inspect. |
| Per-frame Engine reload | Violates STA-001 pin. |
| New capability / `POST /v1/ws-rules` | Violates adapter-only + frozen catalog 31. |
| `drop` = close-both (HTTP meaning) and no omit-frame | Misses #52 “block/drop”. |
| Payload regex / message reassembly | D12 and extra state machine. |
| New HTTP/2 WebSocket match surface | User constraint; D63 already shares `wsx`. |
| Reuse `matchHit` / `requestProtocol` for frame phase | HTTP/1.1 Upgrade would miss `match.protocol: websocket`. |
| Add h2c response-phase `matchHit` so inherit tests can see `late_skip` | `h2cWebSocketTunnel` has none today; do not add eval to satisfy a test. |
| Miss-forward via `TeePayload(src)` after a match read | Consumed `src` → header with no payload (or short write). D67 break. |
| Miss-forward the unmasked buffer | Unmasks client→origin. D67 break. |
| Drain oversized miss “for alignment” when no later winner | Swallows a large data frame. D67 break. |

## Implementation slices (later change; this PR does not land them)

1. **ADR 0015** with D72–D74, frozen names, supersede list (docs/02 and docs/05 sentences only), review triggers. Add to `docs/README.md`, `scripts/checkdocs` `RequiredRootDocs`.
2. **Model + validate + published schema.** `RulePhaseWebSocket`, `ActionBlock`, match fields on `RuleMatchSpec`. Hand-edit `api/jsonschema/labmitm.dev.v1alpha1.json` (not rewritten by `scripts/generate`). Widen `phase` and `action.type` enums; add the three match properties. Go `validateRules` enforces action-vs-phase and frame-field-vs-phase. `TestSchemaListsModelJSONFields` stays green.
3. **`internal/rules`.** Extend match input with `Opcode`, `Direction`, `Payload []byte`. `Match("websocket", …)` first-match with `Protocol` forced by the caller to `websocket`. Helper for “must load payload?”. Unit tests: default-off, AND, first-wins, opcode/direction/payloadContains, `match.protocol: websocket` hits / `http/1.1` misses, empty match, request-phase item does not win on `Match("websocket")`, oversized `payloadContains` is a miss and a later opcode-only item can still win, helper does not demand a load on oversized or on an earlier opcode-only winner.
4. **`internal/proxy` pump.** Grow `inspectUpgrade` to take the matchHit `host` + upgrade `*http.Request`. Store sess + snapshot on `wsInspect` (fields do not exist today). Implement the **Pump I/O** contract. Do not run websocket hits through `runRequestRules` / `Mutates`.
5. **Adapters.** No new REST/MCP tools. Map `frames[].action` in REST and MCP GET-by-id DTOs. `schema.get` serves the updated JSON Schema. Parity: apply `replaceRules` with a websocket-phase item on both transports; GET-by-id contract for `action` + `ruleIds`.
6. **Docs in the same implementation change:** `docs/02-proxy-semantics.md`, `docs/05-rules.md` (phase table + actions + protocol input; h2c stays no response-phase eval), `docs/06-state-and-configuration.md` (validate lines), `docs/04-flow-store.md` (`action` on frames), `docs/08-rest-api.md` (GET-by-id `action`; list still omits `frames`), `docs/09-mcp-api.md` if it describes frame JSON, `docs/11-observability.md` (`action=block` token; `drop` shared; `ws_frames_total` still forwarded-only), `docs/12-testing-strategy.md`, `docs/known-limitations.md` (inspect Reset-only; pin table; payloadContains cap; h2c no response-phase eval), `CHANGELOG.md` Unreleased (include canonical-JSON churn for existing `rules.items`), `docs/README.md` ADR row. `Last reviewed` on touched numbered docs. Overlay stays `inspectFrames` off.
7. **UI.** Not required. Follow-on: Frames tab badge.

## Tests (implementation change)

A bug-fix/feature must fail before the hook exists.

| Layer | What |
|---|---|
| Rules unit | First-match websocket phase; opcode; direction; payloadContains; empty match; `rules.enabled` false matches nothing; request-phase item does not win on `Match("websocket")`; `match.protocol: websocket` hits; `http/1.1` / `h2` miss; oversized `payloadContains` is a miss and a later opcode-only item can still win; load-helper: no load on oversized; no load when an earlier opcode-only item would win. |
| Config | Valid: websocket-phase drop/block with inspectFrames on and off. Invalid: unknown phase, `block` on request, `body` on websocket, unknown opcode, unknown direction, non-empty `opcode` on `phase: request`. Reserved keys unchanged. Empty-spec revision can stay stable. No revision goldens today (`TestConfigCompat` round-trips); changelog notes canonical-JSON churn for non-empty `items[]`. |
| Proxy (`ws_test.go` + existing 101 transcript) | Keep `upgrade-websocket-frames.txt`. Drivers: (1) inspect on + drop text client frame → origin never sees it, later ping still forwarded; (2) inspect on + block binary → both sides closed, later frames not delivered, `Error` empty, `State=completed`; (3) inspect **off** + websocket-phase drop → copy path, origin sees the frame, no `drop` hit; (4) `TestWebSocketLateSkip` still `body` → `late_skip`; (5) response-phase `drop` (and `delay`) + inspect on + websocket-phase items present → 101 still `late_skip`, response item does not omit frames; (6) `match.protocol: websocket` on HTTP/1.1 inspect drop fires; `http/1.1` misses; (7) dropped `close` → loop continues, later ping still evaluated; (8) `payloadContains` on **masked** client frames compares unmasked bytes; (9) `continuation` + `payloadContains` is fragment-only; (10) declared length > pinned `maxBodyBytes` + `payloadContains` miss + **later opcode-only drop** → payload discarded, origin never sees it, no `Error=websocket`; (11) close length 1 (and control >125 via `ReadHeader`) still `Error=websocket` when websocket-phase rules exist; (12) HTTP/1.1 inspect + `pathPrefix: /ws` + `headerName` drop (operator sequence; proves snapshot extraction, not `Flow.URL` / `req.Host`); (13) second-frame `payloadContains` after prior frames consumed part of the capture budget — declared length ≤ **full** `maxBodyBytes` still content-matches (not `storeRemain`); (14) `replaceStoreCaps` after pin does not change `payloadContains` visibility; **(15) `payloadContains` miss + frame forwarded with original mask** (client→origin stays masked; origin sees the same wire key / masked payload); **(16) oversized + `payloadContains` miss + no later winner + frame still streamed in full, no `Error=websocket`**. |
| Snapshot pin | Cleartext: in-flight inspect socket keeps the old Engine; a **new cleartext Upgrade** sees the new drop. Inner: `replaceRules` after CONNECT is established, then inner Upgrade — still the **old** Engine. `setFeature rules.enabled=false` on an already-open inspect socket: frames **still** match. |
| Inherit only | Thin **new** sibling of D63 Extended CONNECT with `inspectFrames` + websocket-phase drop on the shared pump (existing D63 tests are handshake-only). Method remains `CONNECT`; do not assume `pathPrefix: /ws`. Inner D63 `:status=200` + response-phase `drop`/`delay` still `late_skip` and does not omit frames. **Do not** add a client-facing h2c response-phase `matchHit` or an h2c `late_skip` inherit assertion. Flag-off illegal h2 Upgrade stays RST, no flow. h2c later-stream pin is residual (same PRI rule as D74). |
| Parity / contract | REST + MCP `replaceRules` apply; `schema.get` enums include `websocket` / `block`. GET-by-id `frames[].action` (`drop`/`block` present; forwarded omitted) and `ruleIds` contains the websocket-phase id. List omits `frames`. No new catalog row. |
| Race | `make test-race` on `internal/proxy` (two pumps now eval + capture). |
| Generate | `make generate` / `verify-generated` if OpenAPI/MCP goldens mention rule enums. JSON Schema is hand-updated. |

`make test-config-compat` and `make test-docs` are mandatory for the implementation change.

## Operator sequence (accepted)

```text
1. Bootstrap YAML: protocols.websocket.inspectFrames: true  (websocket.enabled true, default)
2. POST /v1/state:reset          # D51'; wipes flows; new sessions may decode
3. POST /v1/changes:apply        # replaceRules; live on the next pin (see D74 table)
     rules.enabled: true
     items:
       - id: drop-secret
         phase: websocket
         match: { pathPrefix: /ws, opcode: text, payloadContains: secret }
         action: { type: drop }
       - id: kill-binary
         phase: websocket
         match: { opcode: binary, direction: client }
         action: { type: block }
```

Same payload on MCP `mitm_change_apply`. `setFeature` `rules.enabled` arms/disarms the master switch for **not-yet-pinned** sessions only (same table as `replaceRules`). It does not change an open inspect socket or a later inner Upgrade on a CONNECT that already pinned.

Cleartext `pathPrefix: /ws` matches an HTTP/1.1 Upgrade to `/ws`. D63 / h2c requires the bootstrap `:path` to carry that prefix; `Method` is `CONNECT`.

## Residuals (document in known-limitations when implementing)

- `inspectFrames` is Reset-only. Frame rules without that Reset never fire.
- Pin table (D74): open sockets, later inner upgrades on a pinned CONNECT, and later h2c streams on a pinned PRI do not see `replaceRules` / `setFeature rules.enabled`.
- `payloadContains` cannot see frames whose declared size exceeds the pinned visibility cap (fail-open miss; first-match continues). Oversized miss with no later winner is streamed (D67), not swallowed.
- No per-message reassembly; continuation frames match as `continuation`.
- Dropped `close` does not end the inspect loop; idle/session timeouts still apply.
- Client-facing h2c Extended CONNECT has no response-phase eval (unchanged). Inner D63 200 is `late_skip`.
- HTTP block modes and frame `delay` are not this change.
- Inspector Frames tab may not badge `action` until a UI follow-on.
- Extended CONNECT inherits the pump; this is not a new h2 WebSocket product. Bootstrap method/path differ from HTTP/1.1 Upgrade.
- Canonical JSON of any non-empty `rules.items` list grows three empty match keys.

## Implementation-change completion commands

`make format lint generate verify-generated test test-race test-parity test-config-compat test-docs` plus the proxy/rules packages under `make test`. Fuzz/container/web only if those surfaces change. Placeholders must not be added.

## Skeptic-plan-review

Process: never skip sweep 1; each sweep is a fresh skeptic; cap 3 then **BLOCKED**. Stop at **ACCEPT** or **BLOCKED**. Nothing is implemented either way.

Prior cycle ([PR #56](https://github.com/hilather/go-lab-mitmproxy/pull/56)) reached BLOCKED on the miss-forward I/O. This file is a new cycle. Settled items from that cycle are kept (phase split, D51', STA-001 pin table, catalog 31, forced `in.Protocol=websocket`, no new h2 websocket surface, D12). This revision applies the three remaining unblocks: wire-byte miss forward, `wsInspect`/host snapshot facts, no h2c response-phase `matchHit`.

### Sweep 1

Pending.

### Sweep 2

Pending.

### Sweep 3

Pending.

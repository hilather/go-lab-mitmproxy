# Plan: Configurable QA block modes

Status: Proposed (plan only; not implemented)
Owners: Rules, Proxy, Application
Last reviewed: 2026-08-28 (skeptic sweep 1 folded)
Related: [issue #52](https://github.com/hilather/go-lab-mitmproxy/issues/52), [docs/05-rules.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/05-rules.md), [docs/02-proxy-semantics.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md), ADR draft 0013 (this document)
Skeptic: sweep 1 BLOCKED (2 blockers folded); sweep 2 pending

PLAN ONLY. This file is the implementation contract. Do not implement from this PR.

## Verdict

`PENDING` until skeptic-plan-review reaches `ACCEPT` or `BLOCKED` (cap 3 sweeps). Sweep 1 blockers are folded below.

## Goal

Add the #52 block modes — silent TCP close/RST, HTTP status, hang-until-timeout, redirect — as live `spec.rules` actions, configurable through the existing REST/MCP `replaceRules` path. Do not break today’s `drop` / `status`. Do not add a parallel matcher, chaos engine, capability ID, or catalog row.

Issue wording → product spelling:

| #52 name | Product | Today |
|---|---|---|
| `http_status` | existing `action.type: status` | synthesize 400–599; request-phase no Dial |
| (close after status) | existing `action.type: drop` | optional `action.status` (default 403) then close |
| `silent` | new `action.type: silent` | no HTTP bytes; TCP RST or FIN |
| `hang_until_timeout` | new `action.type: hang` | hold, then silent close |
| `redirect` | new `action.type: redirect` | synthesize 3xx + `Location`; request-phase no Dial |

Do **not** add an `http_status` alias. Two spellings for one action would split `KnownRuleAction`, metrics, and tests. Document the mapping in [docs/05-rules.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/05-rules.md).

## Non-goals

- Parallel `spec.qa` / `spec.blocks` engine, weights, hash-v1, or random (D12).
- New capability IDs, REST paths, MCP tools, or `catalog()` rows. Native table stays 30 `/v1` rows.
- Reset-only feature flags. New types ride live `replaceRules` (same as today’s items).
- Changing `drop` (default 403) or `status` (400–599, default 502 when `action.status` is 0).
- Widening `action.status` to 3xx. Redirect uses its own field.
- Rules on raw CONNECT / SOCKS tunnels (still no inner HTTP).
- Mid-stream WebSocket frame block (#52 sibling). Response-phase after `101` stays `late_skip`.
- Bandwidth throttle (#52 sibling).
- 407 / `Proxy-Authorization` (#52 sibling). HTTP hop stays unauthenticated (D17 remainder).
- Following redirects (`CheckRedirect` unused; D21).
- Handshake-failure blind tunnel (D20). `type: silent` is an operator rule, not a TLS fallback.
- UI rule editor. Inspector already shows captured flows.
- Third-party MITM/proxy libraries. Production Dial idents stay in `internal/proxy` only.

## Current behavior (must not change)

Normative: [docs/05-rules.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/05-rules.md). Code: `internal/rules`, `internal/proxy/rules.go`, `internal/config/validate.go`.

- Master switch `spec.rules.enabled` default-off. First enabled AND match wins.
- STA-001 compiles `snapshot.Rules` (`*rules.Engine`). Proxy pins Engine once per request / CONNECT. Live `replaceRules` swaps the snapshot; in-flight keep the Engine they already matched.
- `drop` request: write optional status (default 403) + optional headers/body; no Dial; capture; `handled=true`.
- `drop` response: if headers not flushed, send `status` or 502; if already flushed, `late_skip`.
- `status` request: no Dial; synthesize 400–599 (0 → 502); optional headers/body.
- `status` response: replace status line; headers/body as specified.
- `delay` 0–30s then continue. Must not steal `UpstreamTimeout` (existing test).
- Raw CONNECT: no rules. WebSocket mutating response after `101`: `late_skip`.
- `KnownRuleAction`: `breakpoint | drop | delay | status | header | body`.
- `action.status` empty/0 or 400–599. Body replace ≤ 64 KiB. Breakpoint timeout 1s–60s.
- Metrics: `labmitm_rule_hits_total{action}` (existing counter; new label values only).
- REST/MCP are adapters. Domain in `internal/rules` + `internal/proxy` (+ validate in `internal/config`, types in `internal/model`). Handlers must not grow independent logic.

## Why an ADR

[docs/02-proxy-semantics.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md) forbids new request classes, replies, or limits without an ADR. Silent RST/FIN, hang, and synthesized 3xx are new replies. `KnownRuleAction` is a closed set.

This is **additive** `labmitm.dev/v1alpha1` (ADR 0008 D22 pattern), not a `v1beta1` bump, and **not** a D51 Reset-only flag. Empty `spec: {}` still materializes `rules.enabled: false`. Existing `drop` / `status` YAML keeps today’s meaning.

**Catalog does not grow.** No new capability IDs. Live apply stays `changes.plan` / `changes.apply` / `mitm_change_plan` / `mitm_change_apply` with `op: replaceRules` (`mitm.admin`). `schema.get` / `labmitm://schema/config` keep serving [api/jsonschema/labmitm.dev.v1alpha1.json](https://github.com/hilather/go-lab-mitmproxy/blob/main/api/jsonschema/labmitm.dev.v1alpha1.json); the file’s `ruleAction` enum grows.

Implementation writes `docs/adr/0013-qa-block-modes.md` from the draft below and registers it in `scripts/checkdocs` `RequiredRootDocs` plus [docs/README.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/README.md). This plan PR does **not** add the ADR file (plan only).

## Draft ADR 0013 (extract on implement)

**Title:** QA block modes as additive rule actions (D69)

**Status (when filed):** Proposed → Accepted with the implementing PR.

**Context:** #52 wants silent TCP close/RST, HTTP status, hang-until-timeout, and redirect, live via MCP/REST. Today `drop` always writes an HTTP status (default 403) and `status` synthesizes 400–599. Those two stay. A second engine would violate D12 and split live apply.

**Decision D69 — QA block modes extend `action.type`, not a parallel engine.**

1. New types: `silent`, `hang`, `redirect`. `http_status` is the existing `status` type (no alias).
2. `drop` and `status` semantics are frozen. `action.status` remains empty/0 or 400–599.
3. Silent HTTP/1.1 (and the TCP under an HTTP/1.1 intercept hop): no HTTP bytes; `close: rst` (default) is `(*net.TCPConn).SetLinger(0)` then `Close`; `close: fin` is a normal `Close`. After Hijack, never return that conn to `http.Server` (D19). Intercept hops wrap the TCP (`wrapHijacked` → `*readerConn`); `rst` must recursively unwrap to `*net.TCPConn` (see Close mode). Do not Hijack `captureRW` (h2c is not a Hijacker).
4. Silent HTTP/2 (inner `h2` or client-facing h2c): **RST_STREAM on that stream only**. Do not GOAWAY or close the CONNECT/h2c TCP (D37 / D44 / D64). Both `rst` and `fin` are RST_STREAM `CANCEL` via a new `http2x` sentinel (not `ErrInnerCONNECT`, not default `INTERNAL`). HTTP/2 has no byte-less FIN analog without HEADERS. Every hop that today turns “no response” into HTTP (h2c `captureRW.response()` 500, `roundTripInnerH2` `badGatewayH2` / origin fallback, `innerH2Tunnel` 403) must take the sentinel instead.
5. Hang is deterministic: required `hang.timeout` ∈ [1s, 30s], then the silent close of (3)/(4). Not operator-resumable (that is `breakpoint`). Cancel on `ctx` / process stop. Eval clamp `min(hang.timeout, sessionTimeout)` when `sessionTimeout > 0`, same shape as breakpoint vs `store.maxWait`.
6. Redirect synthesizes 301/302/303/307/308 (default 302) plus required `redirect.location`. Request-phase does not Dial. The proxy does not follow the Location (D21).
7. Live apply is existing `replaceRules`. In-flight sessions keep the old Engine. No new capability IDs. `catalog()` stays 30 `/v1` rows.
8. D12 stands: first-match, default-off, no weights/hash/random. Hang is a fixed timeout, not a chaos engine.
9. D20 stands: intercept handshake failure still closes both sides and stores `tls_handshake` / `upstream_tls`. It is not `type: silent`.

**Does not supersede:** D7, D12, D16, D19, D20, D21, D37, D44, D51 (Reset-only list unchanged), capability freeze.

**Alternatives rejected:** parallel QA engine; alias `http_status`; widening `action.status` to 3xx; hang-forever (0 or omitted timeout); connection GOAWAY for h2 silent; Reset-only flag for these types.

**Review triggers:** a fourth close mode, hang > 30s, or a request to RST the whole h2 TCP.

## Schema (extend `action.type` / action fields)

`internal/model.RuleActionSpec` grows optional nested structs. `KnownFields(true)` stays fail-closed.

```yaml
action:
  type: silent          # breakpoint | drop | delay | status | header | body | silent | hang | redirect
  silent:
    close: rst          # rst | fin; empty → rst
  hang:
    timeout: 5s         # required when type=hang; 1s–30s
    close: rst          # rst | fin; empty → rst
  redirect:
    location: "https://app.lab.test/login"   # required when type=redirect
    status: 302         # 301 | 302 | 303 | 307 | 308; empty → 302
```

Unused sibling fields stay ignored (today `drop` may carry `delay: 0`). Type-specific **required** fields fail closed.

Constants (names, not capability IDs):

```text
ActionSilent   = "silent"
ActionHang     = "hang"
ActionRedirect = "redirect"

SilentCloseRST = "rst"
SilentCloseFIN = "fin"

RedirectDefaultStatus = 302
```

Legal `redirect.status`: 301, 302, 303, 307, 308 only. 300/304/305/306 and every 4xx/5xx are invalid on this field.

`redirect.location` after trim: non-empty; ≤ 2048 bytes; no CR, LF, or NUL (header injection). Absolute and relative URIs are both legal (RFC 9110). No DNS at validate.

`silent.close` / `hang.close`: empty, `rst`, or `fin`. Anything else `invalid_value`.

`hang.timeout`: required on `type: hang`; ∈ [1s, 30s]. 0, negative, and >30s fail. Do not reuse `action.delay` (0 is legal for `delay` and would make omitted hang look like immediate silent).

Do **not** put `Location` only in `headers.set`. Location is required; `headers.set` remains optional extra headers. If `headers.set` also contains `Location`, `redirect.location` wins (deterministic; D12). Validate may optionally reject the duplicate; prefer overwrite + unit test so apply is not fail-closed on a harmless extra header.

`action.status` on `type: redirect` is **not** the 3xx. A document with `type: redirect` and `action.status: 302` still fails today’s 400–599 rule. Operators use `redirect.status`.

## Validation

`internal/config.validateRules` + `model.KnownRuleAction`. Same path for bootstrap `Load` and live `ValidateLiveApply` (replaceRules already goes through compile + validate).

| Path | Fail when |
|---|---|
| `action.type` | not in the expanded closed set |
| `action.status` | not empty/0 and not 400–599 (**unchanged**) |
| `action.delay` | not in [0, 30s] (**unchanged**, all types) |
| `action.silent.close` | set and not `rst`/`fin` |
| `action.hang.timeout` | type=hang and not in [1s, 30s] |
| `action.hang.close` | set and not `rst`/`fin` |
| `action.redirect.location` | type=redirect and empty / too long / has CR/LF/NUL |
| `action.redirect.status` | set and not {301,302,303,307,308} |

Error shape: existing `validation_failed` + `FieldViolation` (`invalid_value` / `required`). No new domain error codes.

Reserved-key scan is unchanged. `silent`, `hang`, `redirect` are not reserved prefixes. Add a reserved-key regression that `action: {type: silent}` / `hang` / `redirect` is **not** classified reserved (same idea as `acceptSOCKS5` vs `socks*`).

JSON Schema [api/jsonschema/labmitm.dev.v1alpha1.json](https://github.com/hilather/go-lab-mitmproxy/blob/main/api/jsonschema/labmitm.dev.v1alpha1.json) is **hand-maintained** (not `scripts/generate`). Update `ruleAction.type` enum and add `silent` / `hang` / `redirect` `$defs`. `GET /v1/schema/config` and `mitm_schema_get` serve that file — no new capability.

OpenAPI `State.spec` is `{type: object}`; `make generate` is not expected to rewrite the rules enum. Still run `make generate && make verify-generated` so the worktree stays clean.

## Proxy semantics

Domain helpers live in `internal/rules` (`Mutates`, `StatusFor`, new `SilentClose`, `HangTimeout`, `RedirectStatus`, `RedirectLocation`). Application of close/write stays in `internal/proxy` (needs `net.Conn` / Hijack / http2x). `internal/http2x` **must** grow a documented sentinel (`ErrSilentClose`, name illustrative) so `StreamHandler` / `TunnelHandler` can RST without HEADERS **and** the proxy still captures a flow. Map `errors.Is(err, ErrSilentClose)` to `http2.ErrCodeCancel` in `serve.go` (today `herr != nil || resp == nil` is `INTERNAL`; `ErrInnerCONNECT` is `PROTOCOL_ERROR`). Do **not** use `ErrInnerCONNECT` (RST, **no flow**, D48).

### Outcome of `runRequestRulesWrite` / `finishResponseWrite`

Today `handled` means “synthetic HTTP was written.” Silent/hang break that boolean.

Replace the boolean with an explicit result (names illustrative):

```text
ruleContinue    // delay/header/body/resumed breakpoint; maybe Dial
ruleSynthesize  // drop / status / redirect / dropped-breakpoint: write HTTP, no Dial (request)
ruleSilentClose // silent, or hang after timeout: no HTTP bytes
```

`drop` / `status` stay on `ruleSynthesize`. Do not fold them into silent.

**Thread the result to every caller.** A boolean `handled` plus “skip write” is not enough. Today these no-response paths emit HTTP instead of RST:

| Caller | Today if no HTTP write | Required for `ruleSilentClose` |
|---|---|---|
| `roundTripInnerH2` request | `handled && syn == nil` → `badGatewayH2()` (502 HEADERS) | return `(nil, nil, http2x.ErrSilentClose)` after capture; no 502 |
| `roundTripInnerH2` response | `finishResponseWrite` skip `write` → `outResp == nil` → origin `resp` forwarded | same sentinel; **do not** take the `outResp == nil` origin fallback |
| `roundTripH2C` | `serveAbsolute` / `serveOrigDestHTTP` on `captureRW` (not a `Hijacker`). No write → `captureRW.response()` synthesizes **500** HEADERS (`!wroteHeader`) | do **not** Hijack `captureRW`. `serveAbsolute` / `forwardOriginHTTP` must return `ruleSilentClose` to `roundTripH2C`, which returns the sentinel and **must not** call `rw.response()` |
| `innerH2Tunnel` | `handled && syn == nil` → `Tunnel{Status: 403}` then `writeStatus` HEADERS | RST + capture via the same sentinel (not a 403 tunnel ack). Request-phase rules already run on Extended CONNECT websocket |
| HTTP/1.1 `serveAbsolute` | `ResponseWriter` | Hijack + linger/close (not used on h2c) |
| HTTP/1.1 `serveExpectAbsolute` / intercept inner h1 | already hijacked raw conn | linger/close on unwrapped TCP |

Existing inner-h2 drop/status tests (403/418) must keep passing. Implementation sequence must wire the sentinel in the same step as the 502 trap.

### Request phase (all three new types)

- After parse + target guards + match (same hook).
- No Dial / no origin RoundTrip.
- Capture a **completed** flow (not `FlowStateError`). `flowFromReq` / `innerFlow` map any non-empty `ferr` to `FlowStateError` — do **not** pass `rule_silent` / `rule_hang` as `ferr`. Set `Error` after construct (same family as `breakpoint_timeout`: rule outcome, not `dns`/`dial`/`tls_handshake`). `RuleIDs` set. `Status=0` for silent/hang. `Status=redirect.status` for redirect (`Error` empty). Metric `labmitm_rule_hits_total{action="silent"|"hang"|"redirect"}`.
- Session metric `ok` (operator-intended), not `reject`.

### Response phase

- Same hook as today’s drop/status: inside `finishResponseWrite` after upstream headers and **before** `write()`. No new flush-detector. Do not add a path that could `late_skip` live drop/status.
- Silent/hang: do not call `write()` with the origin response; propagate `ruleSilentClose` to the caller (table above). Origin body is drained/captured under existing stream-vs-mutate rules (see Mutates).
- Redirect: replace status + `Location` (+ optional headers/body), then `write()` as `ruleSynthesize`.
- WebSocket `101` is the only existing `late_skip` site (`forward.go`, `intercept.go`). Request-phase silent/hang/redirect may still fire **before** Dial/upgrade. Response-phase match after `101` increments `late_skip` and does **not** RST the upgraded conn (unchanged).

### HTTP/1.1 absolute-form (non-Expect)

`serveAbsolute` on a real `http.ResponseWriter` (client-facing HTTP/1.1): silent/hang **must Hijack before any `WriteHeader`**, apply linger if `rst`, close, and never return the conn to `http.Server`. Drop/status keep `writeClientResponse`.

`serveAbsolute` on h2c `captureRW`: **do not Hijack** (not a `Hijacker`). Return `ruleSilentClose` to `roundTripH2C` instead.

Expect/100 path is already hijacked (`serveExpectAbsolute`). Silent/hang use the raw `client` conn; do not write 100 or a final status.

### CONNECT intercept (HTTP/1.1 inner)

Already on a hijacked conn. Silent/hang close that inner TLS/TCP without an HTTP response. Do not Dial origin. Do not raw-tunnel (D20 remains for handshake failure only).

### HTTP/2 inner and h2c

- Silent/hang: `RST_STREAM` `CANCEL` on the matched stream only, via `http2x.ErrSilentClose`. Other streams on the same CONNECT/h2c TCP continue. Do not GOAWAY; do not `Close` the h2c/CONNECT TCP for one stream.
- `roundTripH2C` must not Hijack `captureRW` and must not call `rw.response()` on `ruleSilentClose`. Orig-dest-on-h2c uses the same `captureRW` path (`serveOrigDestHTTP`) and the same return rule.
- `innerH2Tunnel` (Extended CONNECT websocket, request-phase rules already run): `ruleSilentClose` → sentinel RST + flow, not `Tunnel{Status: 403}`.
- Hang wait runs **outside** the origin mutex (same as request-phase `WaitPaused`, D37/D44). A hung stream must not block another stream’s request-phase rules or origin h2 multiplex (D64).
- Redirect: HEADERS `:status=3xx` + `location` (and optional body DATA), same as today’s status synthesize (`ruleSynthesize`).
- Nested inner CONNECT without `:protocol` stays RST, **no flow** (D48 remainder). Rules still do not create a flow there.

### Raw CONNECT / SOCKS tunnels

No change. No inner HTTP → no match.

### Stream vs mutate (docs/02 table)

| Action | Mutates? | Notes |
|---|---|---|
| `silent`, `hang` | no | capture-only tee if a body exists; request-phase typically no origin body |
| `redirect` | yes | same buffer/`body_skipped` path as `status` |

### Hang vs delay vs breakpoint

| | `delay` | `hang` | `breakpoint` |
|---|---|---|---|
| After wait | continue (may Dial) | silent close | operator Resume/Drop or continue unmodified on timeout |
| Timeout field | `action.delay` 0–30s | `action.hang.timeout` 1s–30s | `action.breakpoint.timeout` 1s–60s |
| Admission slot | held during sleep | held during hang | held during pause |
| Store | none | none | `Insert` paused + `WaitPaused` |

Hang is **not** a chaos engine: one configured duration, first match, default-off. Cap 30s. Cancel on shutdown.

Admission hold is hop-specific (do not overstate):

- HTTP/1.1 absolute-form: `ServeHTTP` holds `gate.acquire` for the request, so hang occupies one in-flight slot for `hang.timeout`.
- Client-facing h2c and intercepted CONNECT: `gate.acquire` is **once per TCP** (`serveH2C`, CONNECT). Hang occupies one stream toward `maxConcurrentStreams`, not an extra gate slot. Sibling streams on that TCP still run.

Eval clamp: `min(hang.timeout, sessionTimeout)` when `sessionTimeout > 0` (default session timeout is 10m, so the 30s cap always wins unless the operator shortens session timeout). Do not steal `UpstreamTimeout` (no Dial).

### Close mode details (HTTP/1.1)

Go API is `(*net.TCPConn).SetLinger(0)` (abortive close / RST on Linux), not `SetLinger(true, 0)`.

`rst` requires a recursive unwrap helper in `internal/proxy` (name illustrative: `tcpConnOf`):

1. `*net.TCPConn` → use it.
2. `*tls.Conn` → `NetConn()` and recurse.
3. `*readerConn` (`wrapHijacked` in `intercept.go`) → inner `Conn` and recurse.
4. Else FIN fallback (`Close` only) and still count the rule hit.

`serveInterceptConn` handshakes on `wrapHijacked(...)`, so `tls.Conn.NetConn()` is `*readerConn`, **not** `*net.TCPConn`. A one-step unwrap always misses RST on intercept HTTP/1.1. The helper is mandatory; the intercept-h1 transcript must distinguish RST from FIN (or the implementation is wrong).

`fin`: `Close` only (no linger).

Do not `SO_LINGER` on the management listener or on origin conns. Do not Hijack or linger `captureRW`.

### Redirect write

`syntheticResponse` today uses `StatusFor` + `BodyReplace`, which do not know `redirect` (would become 502 and drop `body.replace`). Grow `syntheticResponse` (or a sibling builder used only for `type: redirect`) to take `RedirectStatus` / `RedirectLocation` / `BodyReplace` / headers. `StatusFor` for drop/status stays unchanged. If `Content-Type` is unset and body is non-empty, keep today’s `text/plain; charset=utf-8`. Request-phase: no Dial. Response-phase: overwrite status/Location; optional body replace.

## Control plane / parity

No new verbs. Operators already do:

```json
{
  "expectedRevision": "sha256:…",
  "reason": "block login with silent RST",
  "operations": [{
    "op": "replaceRules",
    "rules": {
      "enabled": true,
      "items": [
        {
          "id": "silent-login",
          "enabled": true,
          "phase": "request",
          "match": { "pathPrefix": "/login", "method": "POST" },
          "action": { "type": "silent", "silent": { "close": "rst" } }
        }
      ]
    }
  }]
}
```

REST: `POST /v1/state:validate`, `POST /v1/changes:plan`, `POST /v1/changes:apply`.
MCP: `mitm_state_validate`, `mitm_change_plan`, `mitm_change_apply`.
Same `model.RulesSpec`, same `config.Validate` / `ValidateLiveApply`, same authorization (`mitm.admin`), same idempotency / `expectedRevision` / audit `changes.apply`.

Parity tests: apply an equivalent `replaceRules` document over REST and MCP; assert same snapshot `Rules` and the same validation failures (bad hang timeout, missing location, illegal redirect status, unknown type `http_status`).

In-flight pin: existing live-apply tests keep covering “swap Engine; in-flight drop still uses old Engine.” Add one hang/silent variant only if the existing pin test is drop-specific and would miss a write-path bug.

## Tests (implementation PR; fail before fix)

### Rules unit (`internal/rules`)

- `Known` / `Mutates` / `SilentClose` / `HangTimeout` / `RedirectStatus` / `RedirectLocation` tables.
- Clamp hang timeout; default close `rst`; default redirect 302.
- `StatusFor` for drop/status **unchanged** (403 / 502 / explicit 4xx–5xx).

### Config (`internal/config`)

- Valid: one fixture each for silent rst, silent fin, hang, redirect 302, redirect 307 relative Location.
- Invalid: unknown type `http_status`; hang timeout 0 / 31s / omitted; redirect empty Location; Location with `\r\n`; redirect status 300 / 304 / 403; silent.close `reset`; `action.status: 302` still invalid.
- Reserved-key: `type: silent` is not reserved.
- Normalization / revision: enabling a silent item changes `runtimeRevision`; `spec: {}` still has `rules.enabled: false`.

### Proxy / proxytest session transcripts (`internal/proxy`, `internal/proxytest`)

New transcripts under `testdata/proxy/` (HTTP/1.1 absolute-form):

- `rule-silent-rst.txt` — POST, no HTTP response bytes, origin hits 0, next peek sees reset/EOF.
- `rule-silent-fin.txt` — same, clean EOF.
- `rule-hang.txt` — hold ≥ configured timeout (use 1s in CI), then silent close; origin hits 0.
- `rule-redirect.txt` — 302 + Location, no Dial.

Plus Go tests (existing `startProxy` / `throughProxy` style, like `TestRequestDrop` / `TestRequestStatusSynthesizes`):

- Existing drop (403 + header, no Dial) and status (503 + body, no Dial) remain.
- First-match: silent item before a status item; only silent fires.
- Response-phase silent/redirect before flush; `late_skip` after flush (Expect or captured-tee path already used for drop).
- Intercept inner HTTP/1.1 silent `close: rst`: no origin Dial; recursive unwrap; transcript distinguishes RST from FIN; flow `Error=rule_silent`, `State=completed`.
- Intercept inner HTTP/1.1 silent `close: fin`: clean EOF, not RST.
- Inner h2 request-phase silent → RST_STREAM `CANCEL`, **no** 502 HEADERS; a second stream on the same CONNECT still succeeds; drop/status on h2 still return 403/418.
- Inner h2 **response-phase** silent → RST_STREAM `CANCEL`, origin response is **not** forwarded (`outResp == nil` fallback must not win).
- Client-facing h2c request-phase silent (and orig-dest-on-h2c): RST_STREAM `CANCEL`, **no** 500 from `captureRW.response()`.
- Extended CONNECT websocket request-phase silent (`innerH2Tunnel`): RST + flow, not 403 HEADERS.
- h2 hang does not hold the D44 origin mutex (second stream request-phase proceeds).
- Delay regression still does not steal `UpstreamTimeout`.
- WebSocket 101 response-phase silent is `late_skip`.
- `rules.enabled: false` with a silent item is a no-op.

Do not use `PlayTranscript` for SOCKS BIND/UDP (existing rule). Silent on SOCKS raw tunnels is out of scope.

Hang tests: use 1s timeout, not 30s. Bound with `time.After` / fake clock only if the repo already has one; otherwise real 1s is acceptable. Do not add a random jitter.

### REST / MCP / app

- Contract: `replaceRules` with each new type validates and applies; bad ranges return `validation_failed` with the field path.
- Parity: same operations through MCP tools.
- Live apply: in-flight request that already matched `drop` is unaffected by a subsequent silent `replaceRules`.
- `make test-parity` stays green; no catalog row count change (`TableRowCount` 30).

### Docs / generate / changelog (implementation)

- Update docs/05 table, docs/02 stream-vs-mutate, docs/06 validate bullets, docs/12 RULES-001 fixtures, docs/11 action label values, docs/known-limitations (optional one-liner: hang holds admission).
- ADR 0013 + checkdocs list + docs/README.
- `Last reviewed` on touched numbered docs.
- CHANGELOG Unreleased Added: the three types + mapping of #52 `http_status` → `status`.
- `make format lint generate verify-generated test test-parity test-config-compat test-docs test-changelog`.

This plan PR does not change product behavior and does not need a changelog entry.

## Implementation sequence (later PR, not this one)

1. File ADR 0013 from the draft; expand `KnownRuleAction` + structs + validate + JSON Schema + config fixtures. No proxy behavior yet (validate-only can merge only if docs say types are not wired — prefer one PR that wires them).
2. `internal/rules` helpers + unit tests.
3. Proxy result enum; request/response HTTP/1.1 silent/hang/redirect; keep drop/status on the synthesize path. Recursive `tcpConnOf` + intercept RST transcript.
4. `http2x.ErrSilentClose` → `ErrCodeCancel` (StreamHandler **and** TunnelHandler). Thread `ruleSilentClose` through `roundTripInnerH2` (request 502 trap **and** response `outResp == nil` fallback), `roundTripH2C` (no `rw.response()`), and `innerH2Tunnel` (no 403 ack). Same step as the 502 trap.
5. Live-apply / REST / MCP / parity.
6. Numbered pack, changelog, generate, full required targets.

## Risks

- **No-response → HTTP traps.** `badGatewayH2`, `outResp == nil` origin fallback, `captureRW.response()` 500, `innerH2Tunnel` 403. Named result + `ErrSilentClose` on every hop, not a boolean.
- **Hijack on the ResponseWriter path** for HTTP/1.1 silent/hang only. Never Hijack `captureRW`. Drop/status must not start Hijacking (would change keep-alive / 403 write).
- **Recursive unwrap for SetLinger.** One-step `tls.Conn.NetConn()` is `*readerConn` on intercept. Intercept-h1 RST vs FIN transcript is the tripwire.
- **h2 connection vs stream.** Closing the CONNECT/h2c TCP would stall sibling streams. RST_STREAM `CANCEL` only.
- **Admission fill from hang.** HTTP/1.1 holds a gate slot; h2c/CONNECT do not take a second slot. 30s cap + docs; not a reason to reject the action.
- **D20 confusion.** Tests must keep handshake-fail → `tls_handshake`, not `rule_silent`.
- **`syntheticResponse` vs redirect.** Must not reuse `StatusFor` alone (502).

## Acceptance (implementation)

- #52 modes available as `status` (existing), `silent`, `hang`, `redirect`.
- `drop` / `status` golden tests unchanged in meaning.
- Live `replaceRules` via REST and MCP; in-flight Engine pin holds.
- Catalog still 30 rows; no new capability IDs.
- Ranges fail closed; `http_status` is not a legal type.
- D7 / D12 / D19 / D20 / D21 hold.

## Skeptic-plan-review log

Process: never skip sweep 1; fresh Task skeptic each sweep; fold blockers; cap 3 then `BLOCKED`. Stop at `ACCEPT` or `BLOCKED`. Do not implement.

| Sweep | Agent | Result | Blockers folded |
|---|---|---|---|
| 1 | fresh Task | BLOCKED | (1) h2/h2c/tunnel no-write traps (`captureRW` 500, `outResp==nil` origin fallback, `innerH2Tunnel` 403, `ErrSilentClose`→`CANCEL`). (2) intercept `rst` must recursively unwrap `wrapHijacked`/`readerConn`; one-step TLS unwrap is always FIN. Also folded nits: `State=completed` not `ferr`→`FlowStateError`; `SetLinger(0)`; `syntheticResponse` must know redirect; no new late_skip flush detector; hang admission is per-hop; sentinel in impl sequence. |
| 2 | (pending) | | |
| 3 | | | |

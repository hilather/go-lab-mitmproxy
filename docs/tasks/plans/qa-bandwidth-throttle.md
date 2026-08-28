# Plan: QA bandwidth throttle (not just per-request delay)

Status: **ACCEPT**
Date: 2026-08-28
Issue: [#52](https://github.com/hilather/go-lab-mitmproxy/issues/52) (item: Bandwidth throttle)
ADR: [0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-rules-throttle-action.md) (D69)
Skeptic-plan-review: sweep 1 done; two fresh skeptics; cap 3; **ACCEPT**
Implementation: not started (this PR is plan-only)

## Today (do not re-litigate)

`action.type: delay` is a **0–30s sleep then continue** on the winning request- or response-phase item. It does not pace bytes. Validate: `action.delay` ∈ [0, 30s] (`config.MaxRuleDelay` / `rules.ClampDelay`). Proxy: `sleepDelay` in `runRequestRulesWrite` / `finishResponseWrite`. First enabled match wins. No weights, no hash-v1, no random (**D12**). Master switch `spec.rules.enabled` default **off**.

STA-001 compiles `spec.rules` into `snapshot.Rules` (`*rules.Engine`). The proxy pins that Engine once per request / CONNECT. Live `replaceRules` swaps the snapshot; in-flight sessions keep the Engine they already matched.

REST and MCP are adapters over `internal/app`. Live mutation is `POST /v1/changes:plan` / `:apply` and `mitm_change_plan` / `mitm_change_apply` with `op: replaceRules`. Catalog stays **30 `/v1` rows**. No new capability IDs. Adapters must not grow independent validate or rate math.

Rules do **not** apply to raw CONNECT / SOCKS tunnels. Mutating response rules after a WebSocket `101` are `late_skip`. Replay is **not** a rule action.

Production Dial idents stay in `internal/proxy` only. No third-party MITM/proxy library. No Python mitmproxy surface.

## Goal

Give lab operators a **deterministic bytes/sec body throttle** on matched request and/or response bodies, live-configurable via the existing REST/MCP `replaceRules` path, without a global token-bucket daemon and without collapsing into `delay`.

QA need: a large download (or upload) that trickles so the system under test hits **its** idle/read deadline — not a single 2s pause followed by a full-speed flush.

## Non-goals (this workstream)

- Process-wide or per-connection shared shaper (all flows on a TCP session sharing one bucket).
- Random jitter, loss, reorder, or LabDNS-style chaos (**D12**).
- `0` B/s hang-until-timeout, silent RST, HTTP status inject, or redirect (other #52 items).
- Post-101 WebSocket frame rate or CONNECT/SOCKS splice rate (other #52 item / 1.2 `inspectFrames` residual).
- New `/v1` route, MCP tool, or capability ID.
- UI rule editor, repeater, or fuzzer.
- New module dependency.
- Changing D44 (h2→h1 origin mutex covers RoundTrip + origin drain) or D21 (`Transport.RoundTrip` only).

## Why a rules action is enough (no daemon)

| Requirement | Rules action | Global daemon |
|---|---|---|
| Select host/path/method/header/protocol | existing `match` | would re-implement match or throttle everyone |
| Default-off, first-match, explainable | existing Engine | new always-on limiter |
| Live via REST/MCP | `replaceRules` already | new verb or Reset-only flag (D51) |
| In-flight isolation | session pins Engine | mid-hop rate swap or dual buckets |
| Catalog / parity | no new row | likely a new capability (forbidden here) |
| D12 | deterministic rate | tempting to add burst/jitter |

A daemon is justified only if the product needed a **shared** bytes/sec cap across unmatched traffic or across concurrent streams on one TCP session. Issue #52 does not. Per-message pace on the winning hit is the QA knob. **Do not add a daemon.**

## Decision (D69)

See [ADR 0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-rules-throttle-action.md). Summary:

New `action.type: throttle` with `action.bytesPerSecond`. Compiled into `snapshot.Rules`. Live `replaceRules`. Headers go out immediately; **body** reads are paced. `Mutates=false`.

```yaml
rules:
  enabled: true
  items:
    - id: slow-download
      enabled: true
      phase: response
      match:
        pathPrefix: /big
      action:
        type: throttle
        bytesPerSecond: 8KiB
    - id: slow-upload
      enabled: true
      phase: request
      match:
        method: POST
        pathPrefix: /big
      action:
        type: throttle
        bytesPerSecond: 4KiB
```

Two items are required to pace both directions. First-match-wins forbids combining `delay` and `throttle` on the same phase/match.

## Schema and validate (do not invent)

| Item | Frozen value |
|---|---|
| `model.ActionThrottle` | `"throttle"` |
| `KnownRuleAction` | add `ActionThrottle` |
| `RuleActionSpec.BytesPerSecond` | `int64` `json:"bytesPerSecond"` |
| YAML decode | add `"bytesPerSecond"` to `config.sizeFields` (IEC string; bare number invalid — same as `maxBodyBytes`) |
| JSON Schema | `api/jsonschema/labmitm.dev.v1alpha1.json` `$defs.ruleAction.properties.type` enum grows `throttle`; add `bytesPerSecond` (`$ref` the existing byte-size string def used by store caps). **Hand-edit** this file (it is not `scripts/generate` output). |
| Validate when `type=throttle` | `bytesPerSecond` ∈ **[256, 64MiB]** (`256` … `67108864`) |
| Validate otherwise | no extra check (default 0) |
| Validate error text | `action.type must be breakpoint, drop, delay, status, header, body, or throttle`; `action.bytesPerSecond must be between 256B and 64MiB` |
| Eval clamp | `rules.ClampBytesPerSecond` — out-of-range test-constructed Engines fail closed to 0 (no-op) or to max; **prefer clamp-to-0 below min and clamp-to-max above max**, matching `ClampDelay`’s below-min → 0 behavior |
| Constants | `config.MinRuleBytesPerSecond = 256`, `config.MaxRuleBytesPerSecond = 64 << 20`; `rules` mirrors them (same pattern as `MaxDelay`) |
| Export / canonicalize | `FormatByteSize` via `sizeFields` |
| Reserved keys | `throttle` / `bytesPerSecond` are legal; do not add them to `reservedExact` |
| D51 | **not** Reset-only. Empty `spec: {}` still has no items. Overlay examples stay flags-off and need not grow a throttle item. |

`phase: both` is invalid today (`KnownRulePhase`) and stays invalid.

## Runtime (proxy + rules)

### Limiter (domain, not adapter)

Add `internal/rules/limit.go` (name may vary; keep it in `internal/rules`):

```go
func LimitReader(ctx context.Context, r io.Reader, bps int64, sleep func(context.Context, time.Duration) bool) io.Reader
```

- `bps = ClampBytesPerSecond(bps)`; `bps==0` returns `r` unchanged.
- Each `Read` copies at most `quantum = min(1024, bps)` bytes from `r`.
- After `n>0` bytes, sleep `n * time.Second / time.Duration(bps)` plus a carried remainder so `Σn` over wall time converges to `bps` (integer `time.Duration` must not floor every 1-byte Read to 0 at high rates — carry leftover nanoseconds).
- `sleep` false (cancel / process stop) → return `n` plus `ctx.Err()` or `io.EOF` as appropriate; do not ignore cancel (same contract as `sleepDelay`).
- `Close` delegates when `r` is `io.Closer`.
- No `math/rand`. No `golang.org/x/time/rate`. No Dial.

Proxy passes `s.sleepDelay` (already respects request ctx and `s.ctx`).

### Hook points (all of them)

Throttle is **not** a pre-body sleep. Wrap the body after match, on the tee path:

1. **Request phase** (`runRequestRulesWrite`): `case model.ActionThrottle` → wrap `req.Body` with `LimitReader` when non-nil / not `NoBody`. Return `handled=false`. Do **not** call `prepareRequestBody` (that is the mutate path). `originRequest` / `innerOriginRequest` already tee when `reqCap==nil`; the tee must read **through** the limiter so capture and origin see the same pace (no unbounded prefetch).
2. **Response phase** (`finishResponseWrite`): do **not** sleep before `write`. Fall through to `teeResponse` when `respCap==nil`, then wrap `resp.Body` with `LimitReader` so `write` / `writeClientResponse` / `writeConnResponse` paces client bytes. Headers and status are written at full speed.
3. **Cleartext absolute-form** (`forward.go`) and **orig-dest origin-form** share `runRequestRules` / `finishResponseWrite`.
4. **Intercept inner HTTP/1.1** shares the same helpers.
5. **Inner HTTP/2** (`roundTripInnerH2`): request wrap happens before `RoundTrip` (inside the D44 mutex when origin is HTTP/1.1 — one TCP; a throttled upload occupies it). `drainOriginBody` stays full-speed under that mutex. Response wrap is in `finishResponseWrite` **after** the mutex is released — client-paced, origin already drained. Origin `h2` (D64) does not hold `originMu`.
6. **Client-facing h2c** uses the same request/response helpers on each stream.
7. **WebSocket `101` / Extended CONNECT websocket:** existing `late_skip` before splice / `inspectUpgrade`. Throttle must **not** wrap the upgraded byte copy.
8. **Raw CONNECT / SOCKS BIND/UDP:** no rules. Out of scope.

Increment `labmitm_rule_hits_total{action="throttle"}` via the existing `metrics.ruleHit` path (same as delay). No new metric ID. No new observability catalog row.

### Timeouts and admission

Pacing a 1 MiB body at 256 B/s is about 68 minutes and **will** hit default `upstreamTimeout` (60s) or `idleTimeout` (120s) or eventually `sessionTimeout` (10m). That is correct. Do not add a throttle wall-clock cap. Document in `docs/05-rules.md` that operators must raise those knobs (live `replaceAdmission` for the session gate / pinned deadlines; `http.Server.IdleTimeout` stays Start-time per existing 06-state text) when they want a long trickle.

Cancel: client disconnect and process shutdown abort the sleep the same way delay does.

### First-match interactions

| Winning type | Throttle? |
|---|---|
| `throttle` | pace this phase’s body |
| `delay` | sleep once; full-speed body (unchanged) |
| `header` / `body` / `status` / `drop` / `breakpoint` | unchanged; no implicit rate limit |
| no match / `rules.enabled: false` | unchanged |

A later `replaceRules` does not retcon an in-flight wrap (the limiter already closed over the pinned `Hit.Action.BytesPerSecond`).

## Control plane (adapters only)

No new capability. Domain validate lives in `internal/config.Validate` (and therefore `compiler.Compile` / `app.Plan` / `app.Apply`). REST and MCP decode into `model.Operation` and call `Service`.

Parity cases (same `ChangeIn`, both transports):

1. Valid `replaceRules` with one `throttle` item → apply succeeds; `GET /v1/state` / `mitm_state_get` shows the item; next matching proxy session hits `action=throttle`.
2. `bytesPerSecond` below min, above max, or missing when `type=throttle` → `validation_failed` with the same `FieldViolation.Path` (`operations[0].rules` compile path / `spec.rules.items[i].action.bytesPerSecond`).
3. Unknown `action.type` still fails (enum).
4. Idempotent apply of the same key does not swap twice (existing LRU).

Do **not** re-validate ranges in `internal/control/rest` or `internal/control/mcp`.

`make generate` / `verify-generated` if OpenAPI/MCP embeddings mention the action enum. If they only `$ref` the published JSON Schema or treat `rules` as an untyped object, leave generated files untouched.

## Tests

A bug-fix-style first test is not applicable (greenfield action). Ship failing-before-impl tests in the implementation PR; do not delete existing delay tests.

| Layer | What |
|---|---|
| `internal/rules` unit | `ClampBytesPerSecond`; `LimitReader` with a fake `sleep` that records durations (no wall clock): N bytes at R B/s sleeps `N * time.Second / R` (remainder-correct); `bps==0` is a passthrough; cancel returns promptly; `Close` propagates. First-match still prefers an earlier enabled `delay` over a later `throttle`. |
| `internal/config` | valid fixture `testdata/config/valid/rules-throttle.yaml`; invalid fixtures for `0`, `255B`, `65MiB`, bare number `8192`, unknown type (existing unknown-action path). `make test-config-compat`. |
| `internal/app` | `TestReplaceRulesThrottleValidate` (mirror `TestReplaceRulesDelayValidate`); happy-path apply compiles Engine that `Match`es `ActionThrottle`. |
| `internal/proxy` + `proxytest` | Session: 32 KiB origin body, response `bytesPerSecond: 8KiB` → client elapsed **≥** ~4s (lower bound only, same style as `TestRequestDelay`); headers/status visible before the body finishes (prove it is not `delay`); `RuleHits(ActionThrottle)≥1`; body bytes intact. Request-phase POST: origin handler timestamps first vs last body byte, lower-bound gap. Empty GET: hit recorded, no extra multi-second stall. `101` upgrade: `late_skip`, no throttle on the splice. Optional inner-h2: response throttle does not hold `originMu` across the client trickle (second stream can RoundTrip). |
| REST/MCP parity | cases above through both adapters (`make test-parity` plus an explicit shared-domain test). |
| Race | limiter + cancel under `make test-race` (unit is enough; do not hide sleeps with broad retries). |

Do **not** assert exact wall-clock equality. Do **not** add `time.Sleep` in production tests beyond the limiter under test.

## Documentation (implementation PR)

Update in the same change as code (AGENTS.md rule):

- [docs/05-rules.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/05-rules.md) — action table row; YAML example; validate sentence; first-match + two-item note; timeout residual; `Last reviewed`.
- [docs/06-state-and-configuration.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/06-state-and-configuration.md) — validate bullet for `bytesPerSecond`.
- [docs/12-testing-strategy.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/12-testing-strategy.md) — RULES-001 frozen-fixture line grows throttle.
- [docs/01-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/01-architecture.md) — Related ADRs + D69 row (or a pointer under D12).
- [docs/README.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/README.md) — ADR 0013 (this plan PR already indexes it).
- [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/known-limitations.md) — only if we keep a residual (shared shaper out; 101 splice out). Prefer a short “not a connection shaper” sentence over a new limitation dump.
- `CHANGELOG.md` Unreleased **Added** when behavior ships (this plan PR does not ship it).
- `scripts/checkdocs/main.go` `RequiredRootDocs` — add `docs/adr/0013-rules-throttle-action.md` when the implementation PR treats the ADR as a required root doc (this plan PR already adds the file; implementation must not leave checkdocs stale).
- JSON Schema (hand-edit) + `testdata/config/**`.
- Overlay `examples/labmitm.yaml` stays **without** a throttle item (lab default is capture-only).

Cross-file links stay absolute HTTPS URLs.

## Implementation shape (follow-on; not this PR)

One implementation PR is enough (schema + limiter + hooks + tests + docs). Split only if review size demands:

1. ADR (already in-tree) + model + validate + sizeFields + jsonschema + config fixtures.
2. `rules.LimitReader` + proxy hooks + proxytest + rules unit.
3. app validate test + REST/MCP parity + changelog + numbered-pack edits + `make generate` if needed.

Ownership: `internal/rules`, `internal/model`, `internal/config`, `internal/proxy`. Adapters stay thin. `internal/tlsmitm` / `internal/http2x` must not learn throttle or Dial.

## Completion commands (implementation)

```text
make format
make lint
make generate
make verify-generated
make test
make test-race
make test-fuzz-smoke
make test-parity
make test-config-compat
make test-docs
make test-changelog
```

`make test-container` / `web-*` / `security-scan` are unchanged unless a generated or image contract drifts; run them if the implementation PR touches those surfaces.

## Skeptic-plan-review

Process: never skip sweep 1; each later sweep is a **fresh** skeptic (does not reuse the previous skeptic’s “already answered” comfort); cap **3** then **BLOCKED**. Stop at ACCEPT or BLOCKED. No implementation in this loop.

### Sweep 1 (required)

Reviewer posture: assume the first draft will sneak in a daemon, a new catalog row, or “delay with extra fields.”

| # | Finding | Disposition |
|---:|---|---|
| 1 | New `action.type` is an invariant (`KnownRuleAction`, JSON Schema enum). Shipping without an ADR is forbidden. | **ADR 0013 / D69** included. |
| 2 | A global token bucket would rate-limit unmatched traffic and need a new apply verb or D51 flag. Issue #52 is selectable QA. | Daemon rejected; proof is the table above. |
| 3 | Reusing `delay` would keep headers-and-body waiting. That is not bandwidth. | Separate type. |
| 4 | First-match cannot express “delay then throttle” or “both directions” on one item. Inventing `phase: both` is a new invariant. | Two items. Documented. |
| 5 | `0` B/s is hang-until-timeout (#52 other item). | Rejected at validate. |
| 6 | New `/v1/throttle` or `mitm_throttle_set` would break the 30-row catalog freeze. | Forbidden. `replaceRules` only. |
| 7 | h2→h1 D44: pacing `drainOriginBody` would hold `originMu` for the whole client trickle and stall other streams. Pacing only `finishResponseWrite` after drain paces the client (the QA surface) and releases the mutex. Request-phase throttle **does** hold the mutex for the paced upload — that is one HTTP/1.1 origin TCP, not a bug. | Frozen in D69. |
| 8 | YAML byte sizes reject bare numbers (`testdata/config/invalid/bare-bytes.yaml`). A raw int64 field would accept `8192` in YAML and break the IEC contract. | `bytesPerSecond` joins `sizeFields`. REST apply JSON remains integer bytes on the typed struct (existing cap pattern). |
| 9 | `golang.org/x/time/rate` is a new direct dep with burst semantics we do not want. | Stdlib limiter only. |
| 10 | Wall-clock session tests that assert exact duration will flake. | Lower bound only; unit tests fake `sleep`. |
| 11 | WebSocket/CONNECT splice throttle would be a different product (frame/copy path, not HTTP body). | `late_skip` / no rules. |
| 12 | 30s duration cap on throttle would make a 1 MiB / 8 KiB/s download indistinguishable from “sleep 30s then flush.” | No duration cap; admission timeouts stay. |

Sweep 1 **does not ACCEPT** (findings required plan edits). Plan revised. Continue.

### Sweep 2 (fresh skeptic)

Reviewer posture: first skeptic already liked rules; look for hook holes, clamp holes, and adapter leakage.

| # | Finding | Disposition |
|---:|---|---|
| 1 | `ClampDelay` exists because tests construct Engines without `config.Validate`. A test-constructed `throttle` with `1<<40` must not sleep for centuries. | `ClampBytesPerSecond` at eval; below min → 0 (passthrough), above max → max. |
| 2 | Request wrap that sits **outside** `originRequest`’s tee is correct; wrap **after** tee would also work. Wrap **instead of** tee would drop capture. Plan must forbid skipping the tee. | Hook text: tee when `reqCap==nil`; limiter is the `Body` the tee reads. |
| 3 | Integer `time.Duration(n)*time.Second/bps` is 0 for `n=1` when `bps>1e9` (impossible at 64 MiB/s) **and** is 0 for small `n` at high legal rates (64 MiB/s → 1 byte is 15 ns, OK) but a 1-byte Read at 64 MiB/s is fine; a 1-byte Read at a mid rate can still floor. | Remainder carry required. |
| 4 | `http.Server.IdleTimeout` is Start-time (06-state). A live `replaceAdmission` does not retcon it. Plan must not claim operators can raise idle via `replaceAdmission` alone for the cleartext `http.Server`. | Documented. Session/upstream/pinned tunnel deadlines vs `http.Server.IdleTimeout`. |
| 5 | OpenAPI may not embed the action enum. Instruct generate-if-needed; do not hand-edit generated OpenAPI. | Documented. |
| 6 | Parity tests that only hit REST would miss MCP-local schema drift. | Same `ChangeIn`; both transports; domain errors compared. |
| 7 | Inner h2 request trailers / `dropH2RequestTrailers` run after request rules. Limiter on `inner.Body` must survive `innerOriginRequest` clone. | `originRequest` clones then tees `out.Body`; wrap `req.Body` before clone so `Clone` copies the limiter. If Clone does not preserve a custom wrapper identity, wrap `out.Body` inside `originRequest` when the pinned hit is throttle — **prefer wrapping in `runRequestRulesWrite` on `req.Body` and verify `Clone` keeps the wrapper** (stdlib `Request.Clone` copies `Body` as the same `io.ReadCloser`). Implementation test: custom `ReadCloser` identity survives `originRequest`. |
| 8 | Metric `action` values are not allow-listed (unlike `reason`). `throttle` is a new series, not a new metric. Observability catalog unchanged. | No OBS ADR. |

Sweep 2 **does not ACCEPT** (clamp, remainder, idle-timeout honesty, Clone note). Plan revised. Continue.

### Sweep 3 (fresh skeptic)

Reviewer posture: two skeptics already blessed D69; look only for remaining invariant breaks. If any remain, **BLOCKED**.

| # | Finding | Disposition |
|---:|---|---|
| 1 | Replay ignores rules today. Adding throttle to Replay would be a new product (operator-originated origin fetch). | Out of scope; consistent with delay. |
| 2 | `features` JSON / `GET /v1/status` does not list rule action types. No K10-style name to freeze. | No status key. |
| 3 | Compat flow REST does not mutate rules. No `/compat` growth. | Confirmed. |
| 4 | `internal/http2x` must not import rules or Dial. DATA frame size is the codec’s; limiter sits on the `io.Reader` the codec already consumes. | Confirmed. |
| 5 | Min 256 B/s is arbitrary but frozen; changing it later is a schema/validate change, not a silent code tweak. | Frozen in ADR + `MinRuleBytesPerSecond`. |
| 6 | Plan PR must not implement proxy hooks or weaken delay tests. | This PR is docs + ADR only. |

No blocking invariant holes. Catalog unchanged. D12/D7/D21/D44 intact. Rules can do the job.

### Verdict

**ACCEPT** (sweep 3 clean). Cap 3 not exhausted by a blocker.

Do not implement in this PR. Follow-on implementation must start from this document and ADR 0013; if an invariant here must change, write a new ADR first.

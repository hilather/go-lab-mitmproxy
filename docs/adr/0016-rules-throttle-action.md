# ADR 0016: Additive `action.type: throttle` (bytes/sec body limiter)

Status: Accepted
Date: 2026-08-28
Decisions: D75
Issue: [#52](https://github.com/hilather/go-lab-mitmproxy/issues/52) (bandwidth throttle item)
Plan: [docs/tasks/plans/qa-bandwidth-throttle.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/tasks/plans/qa-bandwidth-throttle.md)

## Context

`action.type: delay` is a **per-request sleep** then continue. Validate allows `action.delay` ∈ [0, 30s]. The proxy `sleepDelay`s once in the request phase (before dial / RoundTrip) or once in the response phase (after upstream headers, before any client body byte). That is not a bytes/sec limiter.

Issue #52 asks for a bandwidth throttle that is live-configurable via REST/MCP. D12 forbids a random/probabilistic chaos engine. Desired state stays YAML; the allowed QA knob is deterministic, default-off `spec.rules`. First enabled match wins. `internal/compiler.Compile` already materializes `snapshot.Rules` (`*rules.Engine`). Live `replaceRules` already swaps that Engine; in-flight sessions keep the pin they loaded.

A process-wide token-bucket daemon, a new plan/apply verb, or a new capability ID would be the wrong shape: REST and MCP are adapters over `changes.plan` / `changes.apply`. Catalog stays 31 `/v1` rows (`features.get` already landed). This change does not grow the catalog.

`KnownRuleAction` and the published JSON Schema enum are a closed list (`breakpoint | drop | delay | status | header | body | silent | hang | redirect | block` after ADR 0014 / ADR 0015). Adding `throttle` is an invariant change and needs this ADR. It is **not** a D51' Reset-only protocol flag and **not** a `v1beta1` bump (D22 pattern: additive `labmitm.dev/v1alpha1`).

The accepted plan drafted “ADR 0013 / D69”. Those numbers were taken: [ADR 0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md) (D51'), [ADR 0014](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0014-qa-block-modes.md) (D69), [ADR 0015](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0015-websocket-frame-rules.md) (D72–D74). D70 is claimed by the open 407-auth workstream. This file is **0016**. Decision **D75** is this document.

## Decision

**D75 — Rules may include `action.type: throttle`.** The winning item paces **body bytes** of that phase at a deterministic bytes/sec rate compiled into `snapshot.Rules`. Live apply is existing `replaceRules`. No new capability ID. No global token-bucket daemon. No jitter. No third-party MITM/proxy library. No new direct module dependency (`golang.org/x/time/rate` is out).

Frozen operator names:

| Surface | Value |
|---|---|
| `action.type` | `throttle` |
| Rate field | `action.bytesPerSecond` |
| YAML / config document | IEC byte-size string via existing `sizeFields` (`8KiB`, `256B`, `1MiB`). Bare numbers stay invalid. |
| REST apply JSON | IEC string via `CoerceWireTree` / `sizeFields` (same as `maxBytes`: `"8KiB"`). Bare JSON numbers are rejected. |
| MCP apply JSON | integer bytes on the typed `model.RuleActionSpec` (`8192`). Domain `ChangeIn` is `int64`. |
| Range when `type=throttle` | **256 B/s … 64 MiB/s** inclusive (`config.MinRuleBytesPerSecond` / `MaxRuleBytesPerSecond`, mirrored on `rules.MinBytesPerSecond` / `MaxBytesPerSecond`) |
| `0` / missing / below min / above max when `type=throttle` | `validation_failed` |
| Other action types | `bytesPerSecond` is ignored; default `0` is valid |
| Phase | existing `request` \| `response` only. `phase: websocket` is `validation_failed` (frame rules are ADR 0015). No `both`. Two items if both directions are needed. |
| Stream vs mutate (D21) | `Mutates(throttle)=false`. Stay on the capture-only tee path. Do not buffer to `maxBodyBytes` and fail `body_skipped`. |
| Headers / Content-Length | unchanged; first client/origin header byte is not delayed (that is `delay`) |
| Empty / `NoBody` | rule still hits (`labmitm_rule_hits_total{action="throttle"}`); no sleep |
| Raw CONNECT / SOCKS tunnel | rules do not apply (unchanged) |
| WebSocket `101` / Extended CONNECT websocket AfterAck | response-phase `late_skip` (unchanged). Frame shaping is ADR 0015. |
| Replay | not a rule action (unchanged). `proxy.Replay` does not evaluate rules. |
| Limiter | stdlib `io.Reader` wrapper in `internal/rules`. Quantum `min(1024, bytesPerSecond)` bytes per Read; sleep `n * time.Second / bytesPerSecond` (integer division, remainder carried). Context-cancellable (`sleepDelay` contract). Fail-closed clamp at eval. |
| h2→h1 (D44) | request-phase throttle occupies the origin mutex for the paced RoundTrip (one HTTP/1.1 origin TCP). Response-phase throttle runs in `finishResponseWrite` **after** `drainOriginBody`; it paces the **client** write, not the origin drain. Origin `h2` (D64) does not hold that mutex. |
| Timeouts | existing `sessionTimeout` / `idleTimeout` / `upstreamTimeout` remain the safety valve. Do **not** invent a 30s throttle-duration cap (that would collapse throttle into delay). |
| Catalog | 31 `/v1` rows. No `replaceThrottle`. No `replaceProtocols`. No new capability. |

D7, D12, D16, D21, D22, D41, D51' stand. Reserved attack/compat keys stay reserved (`throttle` / `bytesPerSecond` are legal camelCase).

## Consequences

- `docs/05-rules.md`, `KnownRuleAction`, validate error text, and `api/jsonschema/labmitm.dev.v1alpha1.json` `$defs.ruleAction` grow `throttle`.
- `config.sizeFields` gains `bytesPerSecond` so YAML stays IEC-suffixed.
- Proxy hooks wrap `req.Body` / `resp.Body` on the winning hit. Compiler stays `rules.New(spec.Rules)` — no second index.
- Operators who want a multi-minute trickle must raise admission timeouts; defaults (idle 120s, upstream 60s, session 10m) may complete the session as `timeout`. That is intended QA.
- Concurrent matching requests each get the full configured rate (not a shared connection shaper).

## Alternatives considered

- **Global token-bucket daemon / process-wide bytes/sec:** rejected. Issue #52 is live-configurable QA on selected traffic. Rules already match host/path/method/header/protocol and swap live via `replaceRules`. A daemon would need new config, a new apply verb or Reset-only flag, and would rate-limit unmatched traffic.
- **Reuse `action.type: delay` plus `bytesPerSecond`:** rejected. `delay` is sleep-then-continue (headers and body wait). Throttle is headers-immediate, body-paced. Overloading `delay` would break the 05-rules table and existing delay tests.
- **`action.throttle.bytesPerSecond` nested object:** rejected for 1.0 of this feature. `delay` is a sibling scalar. Nested form can be added later only with a new ADR if burst/quantum become operator knobs. Quantum is frozen in code, not YAML.
- **`phase: both` or multi-action items:** rejected. First-match-wins (D12). Two items.
- **`golang.org/x/time/rate`:** rejected. New direct dep. Burst/jitter extras are unused. Stdlib limiter is enough.
- **0 B/s as hang:** rejected. Hang-until-timeout is a different #52 item. `type=throttle` with `bytesPerSecond: 0` is `validation_failed`.
- **New REST/MCP capability:** rejected. `changes.plan` / `changes.apply` + `replaceRules` already mutate `spec.rules` with optimistic concurrency, dry-run, idempotency, audit, and parity.

## Review triggers

Review when a shared connection shaper, jitter/loss, WebSocket frame rate, CONNECT splice rate, or a Reset-only process-wide bandwidth cap is proposed.

# ADR 0014: QA block modes as additive rule actions (D69)

Status: Accepted
Date: 2026-08-28
Decisions: D69
Issue: [#52](https://github.com/hilather/go-lab-mitmproxy/issues/52) (configurable block modes)
Plan: [docs/tasks/plans/qa-block-modes.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/tasks/plans/qa-block-modes.md)

## Context

Issue #52 wants silent TCP close/RST, HTTP status, hang-until-timeout, and redirect, live via MCP/REST. Today `drop` always writes an HTTP status (default 403) and `status` synthesizes 400–599. Those two stay. A second engine would violate D12 and split live apply.

[docs/02-proxy-semantics.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md) forbids new request classes, replies, or limits without an ADR. Silent RST/FIN, hang, and synthesized 3xx are new replies. `KnownRuleAction` is a closed set.

This is **additive** `labmitm.dev/v1alpha1` (ADR 0008 D22 pattern), not a `v1beta1` bump, and **not** a D51 Reset-only flag. Empty `spec: {}` still materializes `rules.enabled: false`. Existing `drop` / `status` YAML keeps today’s meaning.

ADR [0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md) already records D51'. The accepted block-modes plan drafted “ADR 0013 / D69”; that file number is taken. This ADR is **0014**. Decision **D69** is this document. The bandwidth-throttle plan also drafted an ADR 0013 / D69 for `action.type: throttle`; that workstream must take the next free ADR number and the next free decision id (do not overwrite this D69).

**Catalog does not grow.** No new capability IDs. Live apply stays `changes.plan` / `changes.apply` / `mitm_change_plan` / `mitm_change_apply` with `op: replaceRules` (`mitm.admin`). Native `catalog()` stays 31 `/v1` rows (`features.get` already landed).

## Decision

**D69 — QA block modes extend `action.type`, not a parallel engine.**

1. New types: `silent`, `hang`, `redirect`. `http_status` is the existing `status` type (no alias).
2. `drop` and `status` semantics are frozen. `action.status` remains empty/0 or 400–599.
3. Silent HTTP/1.1 (and the TCP under an HTTP/1.1 intercept hop): no HTTP bytes; `close: rst` (default) is `(*net.TCPConn).SetLinger(0)` then `Close`; `close: fin` is a normal `Close`. After Hijack, never return that conn to `http.Server` (D19). Intercept hops wrap the TCP (`wrapHijacked` → `*readerConn`); `rst` must recursively unwrap to `*net.TCPConn`. Do not Hijack `captureRW` (h2c is not a Hijacker). Hijack+linger/close lives in `forwardOriginHTTP` (shared by absolute-form and orig-dest HTTP/1.1).
4. Silent HTTP/2 (inner `h2` or client-facing h2c): **RST_STREAM on that stream only**. Do not GOAWAY or close the CONNECT/h2c TCP (D37 / D44 / D64). Both `rst` and `fin` are RST_STREAM `CANCEL` via `http2x.ErrSilentClose` (not `ErrInnerCONNECT`, not default `INTERNAL`). HTTP/2 has no byte-less FIN analog without HEADERS. Every hop that today turns “no response” into HTTP (h2c `captureRW.response()` 500, `roundTripInnerH2` `badGatewayH2` / origin fallback, `innerH2Tunnel` 403) must take the sentinel instead.
5. Hang is deterministic: required `hang.timeout` ∈ [1s, 30s], then the silent close of (3)/(4). Not operator-resumable (that is `breakpoint`). Cancel on `ctx` / process stop. Eval clamp `min(hang.timeout, sessionTimeout)` when `sessionTimeout > 0`, same shape as breakpoint vs `store.maxWait`. Delay-cancel is not silent (no linger/RST).
6. Redirect synthesizes 301/302/303/307/308 (default 302) plus required `redirect.location`. Request-phase does not Dial. The proxy does not follow the Location (D21).
7. Live apply is existing `replaceRules`. In-flight sessions keep the old Engine. No new capability IDs. `catalog()` stays 31 `/v1` rows.
8. D12 stands: first-match, default-off, no weights/hash/random. Hang is a fixed timeout, not a chaos engine.
9. D20 stands: intercept handshake failure still closes both sides and stores `tls_handshake` / `upstream_tls`. It is not `type: silent`.

**Does not supersede:** D7, D12, D16, D19, D20, D21, D37, D44, D51' (Reset-only list unchanged), capability freeze.

## Consequences

- `KnownRuleAction`, [docs/05-rules.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/05-rules.md), and `api/jsonschema/labmitm.dev.v1alpha1.json` `$defs.ruleAction` grow `silent` / `hang` / `redirect`.
- `internal/model.RuleActionSpec` grows optional `silent` / `hang` / `redirect` objects. Type-specific required fields fail closed.
- HTTP/1.1 silent Hijack is in `forwardOriginHTTP`. `tcpConnOf` unwraps TLS / `readerConn` / existing wrappers. Framed CONNECT `close: rst` after write is stream `RST_STREAM` `CANCEL`, not linger.
- `http2x.ErrSilentClose` maps to `ErrCodeCancel` in StreamHandler and TunnelHandler.
- Metrics keep `labmitm_rule_hits_total{action}` with new label values only.
- REST/MCP stay adapters. Domain in `internal/rules` + `internal/proxy`.

## Alternatives considered

- **Parallel QA engine / `spec.qa`:** rejected (D12; splits live apply).
- **Alias `http_status`:** rejected (splits `KnownRuleAction`, metrics, tests).
- **Widening `action.status` to 3xx:** rejected (`status` stays 400–599; redirect has its own field).
- **Hang-forever (0 or omitted timeout):** rejected (admission fill; hang is not breakpoint).
- **Connection GOAWAY for h2 silent:** rejected (sibling streams on the same CONNECT/h2c TCP must continue).
- **Reset-only flag for these types:** rejected. They ride live `replaceRules` like today’s items.

## Review triggers

Review when a fourth close mode, hang > 30s, or a request to RST the whole h2 TCP is proposed.

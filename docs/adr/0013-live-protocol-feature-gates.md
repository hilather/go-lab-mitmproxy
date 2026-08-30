# ADR 0013: Live protocol feature gates (D51')

Status: Accepted
Date: 2026-08-28
Decisions: D51', D22 carve

## Context

ADR [0008](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0008-additive-v1alpha1-11.md) **D51** closed live apply for 1.1 flags (`acceptSOCKS5` / `acceptSOCKS4`, `listeners.originalDestination`, `protocols.http2`, `compat.flowREST`): bootstrap YAML + Reset only; no new plan/apply verbs. **D22** said new fields default off.

That policy is stricter than the process. Handshake NextProtos already come from the session snapshot (D46). `dispatchConn` already calls `liveSpec()` per peeked conn. Compat mux already re-reads `liveSpec()`. Binding `origLn` is the expensive case. Reset also wipes the flow inbox (D3), so toggling HTTP/2 or SOCKS for QA destroys captured evidence.

WebSocket 101 is always on and is not a YAML knob. Labs that need “Upgrade must fail closed” cannot express that except via `spec.rules` after the 101 (`late_skip`).

ADR 0008’s review trigger is this request: *“or a live-apply verb is requested for these flags.”*

This ADR **replaces D51 with D51'** and **carves D22**. It does **not** repeal D22 for 1.1 opt-in flags. It does **not** live-rebind orig-dest. It does **not** make 1.2 nested flags live ([ADR 0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) still requires a new ADR for that). **D7, D16, D19, D20, D21 stand.** Resolve-then-guard is unchanged: every A/AAAA is still checked; a disabled hop 403s **before** DNS / Dial.

This ADR recorded D51' before schema / `setFeature` / hop 403 / `features.get` / Status listing landed. Those surfaces **are** on this process now.

## Decision

**D51' — Listener binds and addresses are bootstrap + Reset only. Hop-protocol and accept-mux booleans that the running process already consults from the session snapshot or `liveSpec()` are live-applyable via `setFeature` (and `replaceCompat` for the compat subtree).** `maxConcurrentStreams` continues to ride `replaceAdmission`. `replaceTLS` remains the intercept verb and still rotates generate-mode CA when the TLS spec changes.

**D22 carve (not repeal) — 1.1 opt-in flags stay default-off** (`http2`, `acceptSOCKS5`/`acceptSOCKS4`, `originalDestination`, `compat.flowREST`). **Gates whose zero value would change 1.0 hop behavior** (`websocket`, `connect`, `absoluteForm`) **default on** at `applyDecodeDefaults`. `ui.enabled` remains the 1.0 D13 true default.

Empty `spec: {}` hop behavior is unchanged: HTTP/1.1 + SOCKS-close + no orig-dest + no `/compat` + WebSocket 101 still on. Canonicalize of empty spec **grows** those three enabled objects.

### Live vs Reset-only

| Feature ID | YAML path | Default | Apply mode | Pin granularity | Verb |
|---|---|---|---|---|---|
| `protocols.http2` | `spec.protocols.http2.enabled` | `false` | **live** | **next CONNECT** (ALPN + inner proto from pinned `ruleSession`) | `setFeature` |
| `protocols.websocket` | `spec.protocols.websocket.enabled` | `true` | **live** | **cleartext: next request** on **both** `:8888` absolute-form (`serveAbsolute`) **and** orig-dest origin-form (`serveOrigDestHTTP`), after `beginSession`, before DNS. **inner HTTP/1.1: next CONNECT / SOCKS CONNECT / orig-dest TLS** (`roundTripInner` does `pinned.fork()`) | `setFeature` |
| `protocols.connect` | `spec.protocols.connect.enabled` | `true` | **live** | **next forward-proxy CONNECT** (after orig-dest D57, before Hijack / `metrics.accept()`). SOCKS CONNECT is a **different** ID. Orig-dest tagged CONNECT stays 400 regardless of this flag | `setFeature` |
| `protocols.absoluteForm` | `spec.protocols.absoluteForm.enabled` | `true` | **live** | **next absolute-form request** (`beginSession`). Orig-dest origin-form is **not** this flag (D31) | `setFeature` |
| `listeners.proxy.acceptSOCKS5` | `spec.listeners.proxy.acceptSOCKS5` | `false` | **live** | **next peek** (`dispatchConn` `liveSpec()`) | `setFeature` |
| `listeners.proxy.acceptSOCKS4` | `spec.listeners.proxy.acceptSOCKS4` | `false` | **live** | **next peek** | `setFeature` |
| `listeners.originalDestination` | `spec.listeners.originalDestination.enabled` | `false` | **reset** | n/a — `Start` binds `origLn` | `reset` |
| `compat.flowREST` | `spec.compat.flowREST.enabled` | `false` | **live** | **next management request** (`compatEnabled()` / `liveFlowREST`) | `setFeature` |
| `tls.intercept` | `spec.tls.intercept` | `false` | **live** | **next CONNECT** | `replaceTLS` |
| `rules.enabled` | `spec.rules.enabled` | `false` | **live** | **next request / CONNECT** (engine pointer on `ruleSession`) | `setFeature` |
| `ui.enabled` | `spec.ui.enabled` | `true` | **live** | **next UI request** (`UIEnabled` reads `svc.Active()`) | `setFeature` |

**Reset-only (not catalog toggle rows):** `originalDestination` **address**, `listeners.proxy.address`, `listeners.management.address`, management TLS files, `observability.metrics.listen`.

**1.2 nested flags stay Reset-only** (this ADR does not reopen [ADR 0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md)): `acceptBind` / `acceptUDPAssociate` / `acceptUserPass`, `protocols.http2.clientCleartext` / `origin` / `extendedConnect` / `capturePush` / `grpcDecode`, `protocols.websocket.inspectFrames`.

`compat.flowREST.pathPrefix` is not a `setFeature` ID (`setFeature` is boolean-only). It is live-writable via `replaceCompat` only. `ui.enabled` is live `setFeature` from REST/MCP and from Status after a gated off-confirm ([ADR 0018](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0018-status-ui-enabled-apply.md) D77).

`Feature.Verb` is one frozen token per ID: `setFeature` for every boolean `setFeature` can write; `replaceTLS` for `tls.intercept`; `reset` for `listeners.originalDestination`. `replaceCompat` (prefix) and `replaceRules` (full subtree) remain apply verbs in [docs/06-state-and-configuration.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/06-state-and-configuration.md); they are **not** `Feature.Verb`. Status toggles `applyMode=live && verb=="setFeature"` (including `ui.enabled` after ADR 0018 gated off-confirm).

### Mutation

**`setFeature` is the only protocol/accept mutation.** Plus `replaceCompat` (enabled **and** `pathPrefix`). No `replaceProtocols` / `replaceProxyAccept`. Full subtree replace of nested `ProtocolGateSpec` with JSON/Go zero `false` would flip default-true gates if a caller omitted them.

Closed `setFeature` ID switch:

| ID | Writes |
|---|---|
| `protocols.http2` | `spec.protocols.http2.enabled` |
| `protocols.websocket` | `spec.protocols.websocket.enabled` |
| `protocols.connect` | `spec.protocols.connect.enabled` |
| `protocols.absoluteForm` | `spec.protocols.absoluteForm.enabled` |
| `listeners.proxy.acceptSOCKS5` | `spec.listeners.proxy.acceptSOCKS5` |
| `listeners.proxy.acceptSOCKS4` | `spec.listeners.proxy.acceptSOCKS4` |
| `compat.flowREST` | `spec.compat.flowREST.enabled` (prefix unchanged) |
| `rules.enabled` | `spec.rules.enabled` (items unchanged) |
| `ui.enabled` | `spec.ui.enabled` |

**Rejected IDs** (`validation_failed`, `FieldViolation` path `operations[i].feature.id`):

- `listeners.originalDestination` — Reset-only; remediation “edit bootstrap YAML and Reset”.
- `tls.intercept` — use `replaceTLS`; flipping `Intercept` remints generate-mode CA (`tlsSpecEqual` is full-spec).
- any other string, including 1.2 nested flags.

There is still **no** apply verb that writes `listeners.originalDestination` or listener addresses. GitOps remains: edit bootstrap, `POST /v1/state:reset` (wipes flows, D3).

Plan of a live ID warns `live_next_connection`: in-flight sessions keep the snapshot they pinned; SOCKS peek and new ServeHTTP/CONNECT see the swap; inner HTTP/1.1 websocket follows the CONNECT pin. Prefix collision with `restPath` / `mcpPath` stays `validation_failed` at `config.Validate` (fail-closed, not a warning).

**Do not** read `liveSpec()` from `roundTripInner` to make inner websocket “next request.” That would violate the CONNECT pin.

### Fail-closed 403

**Disable = reject, not rewrite.** All hop gates 403 `forbidden` **before request-phase rules and before any origin RoundTrip / Dial**. Do not strip `Upgrade` and forward as ordinary HTTP. Hostname-only guards stay insufficient (D16); a disabled hop never reaches `LookupIP`.

- **HTTP CONNECT only:** after orig-dest (D57 stays 400), before Hijack, **before** `metrics.accept()`. Never Hijack a disabled CONNECT. Never `writeHijackedError` for this path. SOCKS CONNECT is **not** this flag.
- **Websocket:** after admission accept, at the start of **both** `serveAbsolute` **and** `serveOrigDestHTTP` (before `resolveThenGuard` / DNS) and in inner `roundTripInner`. A gate only in `serveAbsolute` fail-opens orig-dest HTTP `Upgrade: websocket`.
- **Absolute-form:** only at the start of `serveAbsolute`. Orig-dest origin-form is not that flag (D31). Invalid scheme/host still 400. Absolute `https://` stays 400 `absolute_https` even when the gate is on.

No new domain error code. Data-plane 403 uses `forbidden`. Metric reasons: `websocket`, `connect`, `absolute_form` only (not `feature`). Captured `Flow.Error` is **`forbidden`**. Metric `reason` carries the hop token.

**Inner disabled websocket:** 403 that inner request, keep the CONNECT. `writeConnResponse` 403 **without** `Connection: close`. `roundTripInner` returns **`stop=false`**. Origin handler is not invoked. Follow-up GET on the same CONNECT succeeds. Close both TLS sides **only if the 403 write fails**. Cleartext `writeProxyError` may still set `Connection: close` (client hop only). Inner h2 Upgrade / Extended CONNECT stay RST (D48 remainder); disabled websocket does not need a second h2 path.

### Hop-entry inventory

Every data-plane entry that can produce a captured hop. Implementers must not add a new HTTP entry that skips this table.

| Entry | File | Websocket gate | `protocols.connect` | `protocols.absoluteForm` |
|---|---|---|---|---|
| `PRI * HTTP/2.0` | `handler.go` | n/a (hard close `reason=http2`) | n/a | n/a |
| Forward-proxy HTTP CONNECT | `handler.go` → `serveCONNECT` | n/a on the CONNECT itself; inner via `roundTripInner` | **yes** (after orig-dest, before Hijack/accept) | n/a |
| Orig-dest tagged CONNECT | `handler.go` | n/a | **no** — stays 400 D57 | n/a |
| Absolute-form `http://` | `serveAbsolute` | **yes**, start, before DNS | n/a | **yes**, start, before DNS |
| Absolute-form `https://` | `handler.go` | n/a | n/a | n/a — stays 400 `absolute_https` |
| Orig-dest origin-form HTTP | `serveOrigDestHTTP` | **yes**, start, before dest-IP `resolveThenGuard` | n/a | **no** (D31; origin-form is not absolute-form) |
| Orig-dest TLS (byte `0x16`) | `serveOrigDestTLS` → `serveInterceptConn` | inner `roundTripInner` | n/a | n/a |
| SOCKS5/4 CONNECT | `peek.go` / `serveSOCKSConnect` | accept-mux is a different ID; inner `roundTripInner` if intercept | n/a (SOCKS ≠ HTTP CONNECT) | n/a |
| Inner HTTP/1.1 | `roundTripInner` | **yes** (CONNECT-pinned spec) | inner CONNECT is D48 RST on h2; h1 inner CONNECT is not a 1.0 path | n/a |
| Inner h2 | `http2x.ServeClient` | D48 RST Upgrade / Extended CONNECT, no flow | n/a | n/a |
| Blind CONNECT/SOCKS tunnel | copy loop | n/a (no inner HTTP parse) | n/a | n/a |
| Replay | `replay.go` | already rejects `Protocol=websocket` | CONNECT-metadata already rejected | n/a |

### Derived catalog and listing (accepted direction)

Catalog IDs are YAML paths, **not** a parallel `spec.features` map. Frozen ID order: `protocols.http2`, `protocols.websocket`, `protocols.connect`, `protocols.absoluteForm`, `listeners.proxy.acceptSOCKS5`, `listeners.proxy.acceptSOCKS4`, `listeners.originalDestination`, `compat.flowREST`, `tls.intercept`, `rules.enabled`, `ui.enabled`.

Listing is a new `features.get` capability (`GET /v1/features`, `mitm_features_list`, `labmitm://features`), `mitm.read`, insert **after** `status.get` (`TableRowCount` 30 → 31). Mutation stays on `changes.plan` / `changes.apply`. Compact 1.1 booleans on `status.get` remain; the catalog array is **not** nested under `status.features`. Adapters must not reimplement `featuresFromSpec`. `features.get` **is** on `catalog()` (31 rows).

### Closed product calls

1. **`compat.flowREST.pathPrefix` is live-writable via `replaceCompat` only.** Enabled is already live-read. Collision with restPath/mcpPath stays `validation_failed`. `setFeature` is boolean-only and does not write prefix.
2. **Inner disabled websocket: 403 that inner request, keep the CONNECT.** `writeConnResponse` without `Connection: close`; `roundTripInner` returns `stop=false`. Cleartext orig-dest HTTP Upgrade uses the same websocket helper as `serveAbsolute` (before dest-IP Dial). `absoluteForm` stays off orig-dest.
3. **Status lists all rows; admin toggles live `setFeature` hop/accept rows including `ui.enabled` after a gated off-confirm.** See [ADR 0018](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0018-status-ui-enabled-apply.md) D77. Viewers read-only. Recovery after gate-off is REST/MCP `setFeature ui.enabled: true` or bootstrap YAML + Reset.
4. **Keep `protocols.connect` and `protocols.absoluteForm`.** They are in the schema from the gates PR; they are **not** dropped after goldens exist.

## Consequences

- D51 readers must follow D51' (this ADR) for hop/accept vs bind. 1.2 nested flags remain Reset-only.
- Operators must not be told “all new fields default off” and also shipped default-true hop gates. Docs/06 and known-limitations state the D22 carve.
- `setFeature` / `replaceCompat` **are** live on this process for the closed honor-list including `protocols.websocket` / `connect` / `absoluteForm`. Hop 403 is on this process. `features.get` is on this process (`GET /v1/features`, `mitm_features_list`, `labmitm://features`). Empty `spec: {}` hop behavior stays 1.0 at defaults (websocket/connect/absoluteForm on).
- Catalog is 31 `/v1` rows including `features.get`. `/compat` stays a side table.
- Dial isolation unchanged: no new Dial sites. `internal/tlsmitm` still does not Dial. Target guards still check every resolved A/AAAA.
- D7 is **not** superseded.

## Alternatives considered

- Keep D51; only add listing: rejected. Fails live-reconfigure; WebSocket stays unconfigurable.
- Parallel `spec.features` map: rejected. Second source of truth vs `protocols.http2` / `acceptSOCKS5`.
- Live-rebind orig-dest on apply: rejected. Bind/unbind races with acceptLoop, Ready (D56), hairpin (D34), `ConnContext` dest tags, non-linux fail-closed Start.
- Dedicated `POST /v1/features/{id}` mutation capability: rejected. Would duplicate Apply’s OCC/idempotency/audit.
- Rules-only QA (`match.protocol: websocket` + `drop`): rejected as the *primary* gate. Mutating rules after 101 are `late_skip`; HTTP/2 ALPN and SOCKS peek happen before rules.
- `replaceProtocols` / `replaceProxyAccept` subtree replace: rejected. Nested JSON zeros turn default-true gates off when omitted.
- `setFeature` of `tls.intercept` with a `tlsSpecEqual` exception: rejected. `replaceTLS` and `setFeature` would disagree; generate-mode CA still rotates on `replaceTLS`.

## Review triggers

Review when live-apply of 1.2 nested flags is proposed (needs a new ADR), when orig-dest live bind/unbind is proposed, or when a `replaceProtocols` verb is requested. Status toggling `ui.enabled` was reconsidered in [ADR 0018](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0018-status-ui-enabled-apply.md).

# ADR 0008: Additive v1alpha1 for 1.1 opt-in fields

Status: Accepted
Date: 2026-08-19
Decisions: D22, D25, D41, D51

## Context

LabMITM 1.0 froze `labmitm.dev/v1alpha1` as fail-closed desired state. 1.1 needs SOCKS accept flags, an original-destination listener, HTTP/2 enablement, compat flow REST, `maxConcurrentStreams`, and `match.protocol` without a `v1beta1` bump and without renaming reserved attack/compat keys.

Reserved keys (`socks*`, `tproxy`, `transparent`, `mitmproxy*`, …) stay forbidden forever so YAML cannot look like an attack-tool surface. Legal 1.1 names are the camelCase schema spellings (`acceptSOCKS5`, `originalDestination`, `protocols.http2`, `compat.flowREST`).

## Decision

**D22 — 1.1 is opt-in additive `v1alpha1`.** No `v1beta1`. New fields default off. Decode, normalize, and validate accept them; the proxy does not read them until later workstreams.

**D25 — YAML keys do not use reserved names.** Schema camelCase only. `accept-socks5` is not reserved, then fails `KnownFields`. Testdata `reserved-socks.yaml` / `reserved-tproxy.yaml` stay invalid.

**D41 — Attack-tool reserved keys stay forbidden forever.** Message wording may say “not a LabMITM surface”; the key lists do not shrink.

**D51 — 1.1 feature flags are bootstrap + Reset only:** `acceptSOCKS5` / `acceptSOCKS4`, `listeners.originalDestination`, `protocols.http2`, `compat.flowREST`. No new plan/apply verbs. `maxConcurrentStreams` rides `replaceAdmission` (new TCP sessions only). Listener addresses remain reset-only.

## Consequences

- Empty `spec: {}` still materializes 1.0 loopback defaults; new flags stay false.
- Turning on SOCKS, HTTP/2, orig-dest, or compat requires editing bootstrap YAML and Reset (or process restart).
- Reserved-key fixtures remain a compatibility contract.

## Alternatives considered

- `v1beta1` for 1.1 fields: rejected (D22). Additive default-off keeps GitOps fail-closed.
- Reusing reserved names (`spec.socks`, `spec.tproxy`): rejected (D25, D41).
- Live apply ops for listener/accept/protocol/compat flags: rejected (D51).

## Review triggers

Review when a new 1.1 field is proposed, a reserved key is reconsidered, or a live-apply verb is requested for these flags.

## Notes (D51' / D22 carve)

[ADR 0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md) **replaces D51** with **D51'** (live hop/accept vs Reset bind) and **carves D22**: 1.1 opt-in flags stay default-off; 1.0-preserving hop gates (`websocket`, `connect`, `absoluteForm`) default on at decode. `ui.enabled` remains the 1.0 D13 true default. Remainder of this ADR stands.

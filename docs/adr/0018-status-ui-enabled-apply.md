# ADR 0018: Status may apply `ui.enabled` (D77)

Status: Accepted
Date: 2026-08-30
Decisions: D77
Plan: [docs/tasks/plans/spa-live-apply-controls.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/tasks/plans/spa-live-apply-controls.md)

## Context

[ADR 0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md) closed product call #3: Status lists the 11-row catalog and admins toggle live `setFeature` hop/accept rows **except** `ui.enabled`. The apply mode was already **live**. REST and MCP can `setFeature` `ui.enabled` today. The Status exclusion was UX: turning the inspector off 404s `/` on the next UI request.

ADR 0013’s review trigger included *“when Status toggling `ui.enabled` is reconsidered.”* The operator SPA live-apply workstream is that reconsideration.

This is **LabMITM** ADR 0018 (D77). It is not TacLab ADR 0018 (the frozen naming exception cited under D1).

Disabling the inspector must not disable REST/MCP. Recovery must stay possible without the SPA. Confirm must run only when turning **off**. This ADR does **not** change apply mode, does **not** add a `setFeature` ID, and does **not** make Reset-only IDs live.

## Decision

**D77 — Status may apply `ui.enabled` via the existing `setFeature` verb after a gated confirm.**

1. Confirm **only when turning off** (`enabled: true` → `false`). Turning on is a normal `setFeature` with no confirm.
2. Off-confirm text must say **all inspector routes** (`/`, `/status`, `/flows/…`) 404. `tryUI` declines when UI is disabled; the management server writes `404` `not_found`. REST/MCP stay up.
3. Cancel → no POST.
4. OK → the same `applyChanges` path as other `setFeature` rows (OCC `expectedRevision`, new UUID idempotency key, optional reason, CSRF).
5. Recovery is REST/MCP `setFeature` `ui.enabled: true` or bootstrap YAML + Reset.

`httpAuth` is **not** a second Status `setFeature` exception. HTTP 407 stays `replaceHTTPAuth` ([ADR 0017](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0017-http-proxy-407.md)).

Does not supersede: D6, D7, D13, D22 carve, D51' live vs Reset table, D76.

## Consequences

- Status Features table offers `Toggle ui.enabled` for `mitm.admin`.
- Viewers remain read-only.
- Catalog stays 31 `/v1` rows. `features.get` stays 11 rows.
- Apply mode of `ui.enabled` stays **live**. Reset-only IDs stay Reset-only.
- Operators who gate the inspector off recover from REST/MCP or YAML + Reset. The SPA cannot recover itself after the next UI request 404s.

## Alternatives considered

- Keep Status exclusion forever: rejected. The API already allows live `setFeature`; operators had no in-SPA path and no confirm that the 404 is total.
- Confirm on turn-on as well: rejected. Enabling the inspector is not destructive.
- A new modal kit: rejected. Match existing `window.confirm` on Flows delete.
- Make `ui.enabled` Reset-only: rejected. That would invert ADR 0013.

## Review triggers

Review when a second confirm kit is proposed, when Status is asked to apply a Reset-only ID, when `status.tls.ports` is invented, or when a `setFeature` ID for HTTP auth is proposed.

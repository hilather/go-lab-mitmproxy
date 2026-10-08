# ADR 0021: In-page confirms and plan review

Status: Accepted
Date: 2026-10-04
Last reviewed: 2026-10-06 (#91: item 1 `#app-main` focus fallback for disabled, aria-disabled, detached or page-body openers)
Decisions: D80
Amends: [ADR 0018](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0018-status-ui-enabled-apply.md) (confirm surface only; D77 unchanged)

## Context

[ADR 0018](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0018-status-ui-enabled-apply.md) rejected "a new modal kit" and asked confirms to match the existing `window.confirm` on Flows delete. It names "when a second confirm kit is proposed" as a review trigger. The SPA task plans repeated that rule ([spa-remaining-chrome](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/tasks/plans/spa-remaining-chrome.md), [spa-live-apply-controls](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/tasks/plans/spa-live-apply-controls.md)).

Since then the UI gained several destructive or reviewed actions (Clear, Delete, Drop, Replay, Status and Configuration applies). `window.confirm` cannot show structured content (store generation inputs, plan diffs, warnings), blocks the page, and Status reviewed a plan by printing raw JSON into the browser prompt. The operator UI mocks dated 2026-10-03 (approved by Matt Brewer on 2026-10-03) replace these prompts with in-page confirms and a plan-review panel. This ADR is the review ADR 0018 asked for.

## Decision

**D80 — The SPA uses one shared in-page confirm and one plan-review panel instead of `window.confirm`.** Chrome only: no REST path, request field, capability or MCP change; every request body stays byte-identical.

1. One confirm component (`useConfirm`) renders an `alertdialog` in a body-level portal. While open, the rest of the page is `inert`; Cancel has initial focus; Escape and backdrop click cancel; Tab stays inside; focus returns to the opener. When the opener is disabled, aria-disabled, detached or the page body, focus falls back to the main content (`#app-main`). Cancel sends nothing.
2. One plan-review component shows the reviewed request and plan (revisions, kv, diff, warnings, raw JSON). Configuration shows it in-page; Status shows it in a drawer. Apply sends exactly the reviewed request; the drawer settles once.
3. Every former `window.confirm` (Flows Clear, Delete, Drop, Replay; Status and Configuration `ui.enabled`-off; Configuration store-eviction/force) uses these components. No second confirm kit is added.

D77 is restated unchanged: the `ui.enabled` confirm runs only when turning the inspector off; its text says every inspector route (`/`, `/status`, `/flows/…`) returns 404 and REST/MCP stay up; Cancel sends nothing; OK uses the same `applyChanges` path as other `setFeature` rows; recovery is REST/MCP or bootstrap YAML + Reset.

## Consequences

- `window.confirm` is no longer used in product code. Confirms can carry inputs (the optional expected store generation for Clear/Delete) and structured plan content.
- `inert` and the focus trap are not observable in jsdom; they are verified with a browser keyboard script during review.
- ADR 0020 parity is unchanged: every workflow stays reachable and its evidence tests keep their names and request-shape assertions.

## Alternatives considered

- Keep `window.confirm`: rejected; it cannot show plan diffs or inputs and Status printed raw JSON into it.
- Native `<dialog>` per page: rejected; one shared component keeps behavior identical and avoids several kits.
- A UI library: rejected; no new npm dependencies (`createPortal` is part of react-dom).

## Review triggers

Review when another confirm or modal mechanism is proposed, when a confirm needs to send data the API does not accept, or when D77 confirm wording changes.

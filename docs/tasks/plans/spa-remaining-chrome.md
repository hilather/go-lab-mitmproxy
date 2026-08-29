# Plan: LabMITM remaining SPA chrome (Status / Audit / Reset / Login)

Status: ACCEPT (skeptic-plan-review sweep 1: NO BLOCKING FINDINGS; leftovers folded)
Owners: Operator UI
Last reviewed: 2026-08-29
Approved mock: Matt-approved Mira Flows money view (`after.png`) applied to **all remaining SPA pages**
PR: existing [#67](https://github.com/hilather/go-lab-mitmproxy/pull/67) branch `cursor/flows-split-pane-e0eb`. Do not open a new PR. Do not merge.

This document is an implementation contract. Origin `agent-skills` clone was unavailable; skeptic templates still run from the follow-up prompt.

## Verdict (planning)

Investigate-first. Same product, same routes, same behavior. Chrome only.
**Scope correction:** Shell wrap does **not** count. Restyle the **page bodies** of `/login`, `/status`, `/audit`, `/reset`. Login is signed-out (no sidenav/chips); restyle `LoginPage.tsx` itself. Flows is done. No fuzzer/repeater.

## Problem (verified)

PR #67 shipped Flows split-pane + dark **tokens** on `:root` (`web/src/styles.css` 25–46: bg `#0b0c0e`, elev `#121317`, panel `#181a1f`, fg `#ecece8`, accent `#6ea8d1`, tunnel `#c4a35a`, IBM Plex `@font-face`). Status / Audit / Reset / Login still render as leftover **document interiors**:

| Surface | Evidence | Leftover |
|---|---|---|
| Status | `StatusPage.tsx` 131–268 `<main className="page">` + bare `<h1>` / `<h2>` / `<dl>` / `<table className="data">` | No kicker, no panel card, no chip chrome. Feature `on`/`off` is `.badge` (muted). Intercept is prose (`status.intercept` 137–140), not a tunnel chip |
| Audit | `AuditPage.tsx` 38–72 same `.page` + table or `No audit events.` | No kicker/panel; **no `AuditPage.test.tsx`** |
| Reset | `ResetPage.tsx` 39–75 `.page.page--narrow` + `.stack` / `.field` | Form sits on bare bg; submit uses global `button[type=submit]` |
| Login | `LoginPage.tsx` 41–69 `.page.page--narrow` | Same; signed-out `Shell` has **no** live / `:443` chips (`App.tsx` 52–60) — keep that |
| UA buttons | `styles.css` 280–283 `button { font: inherit; cursor: pointer }` only | Non-submit buttons (Flows **Clear flows**, any future control) keep browser default — paper/gray on many engines. Old navy topbar / Segoe / paper `#eef2f4` / `#fffdf8` / accent `#16324f` are **already gone** from `:root` (`git show f6f38a6:web/src/styles.css`) |
| Modals | Status/Audit/Reset/Login have **no** `<dialog>` / `window.confirm` | Only Flows Clear/Delete use `window.confirm` (`FlowsWorkspace.tsx` 62, `FlowInspector.tsx` 341). Do not add a modal kit |

`:root` already has `color-scheme: dark`. Remaining pages inherit tokens but do not look like the money-view inspector (panel `#181a1f`, rounded bordered boxes, chip-like controls, IBM Plex throughout).

## Non-goals

- New routes, REST/MCP capabilities, catalog rows, apply verbs, or Go domain types.
- Redesigning Status **behavior**: `setFeature`, no `ui.enabled` toggle, no `tls.intercept` toggle, 409 refetch, CA download, `GET /v1/features` catalog (`StatusPage.test.tsx` 119–288 stays).
- Redesigning Reset **behavior**: exact `RESET` phrase + checkbox + `mitm.admin` (`forbidden.ts` `canSubmitReset`).
- Redesigning Login **behavior**: bearer-only, no Basic, no token in web storage (`LoginPage.test.tsx`, `security.test.ts`).
- Redesigning Audit **behavior**: `listAudit()`, scoped copy, empty list.
- Moving or remounting Flows SSE. Do not put `EventSource` on `Shell` or Status.
- Fuzzer, repeater, exploit, HTML preview `innerHTML`.
- Live `GET /v1/state` `tls.ports`. Header **:443 intercept only** stays overlay copy.
- Putting **tunnel-not-decrypt** on Status / Audit / Reset / Login. That chip is a flow classification (`isTunnelNotDecrypt` in `web/src/ui/flowKind.ts`) only.
- Custom modal / `<dialog>` component. Remaining pages have no confirms. Do not replace Flows `window.confirm`.
- New npm runtime dependencies. No Google Fonts CDN. No ADR (chrome only).
- Other repos. New PR.

## Evidence (verified)

| Claim | Evidence |
|---|---|
| Tokens already dark | `styles.css` 25–46 |
| Remaining pages are `.page` documents | `StatusPage.tsx` 115/124/131, `AuditPage.tsx` 22/31/38, `ResetPage.tsx` 39, `LoginPage.tsx` 41, `App.tsx` 82/97 loading |
| Unstyled `button` | `styles.css` 280–283 vs submit 285–291, `.linkish` 161–169, `.btn-danger` 298–303, `.tabs button` 409–415 |
| No Audit tests | `web/src/pages/` has `StatusPage.test.tsx`, `ResetPage.test.tsx`, `LoginPage.test.tsx` — no `AuditPage.test.tsx` |
| Shell chips signed-in only | `App.tsx` 52–60 |
| Flows SSE owned by workspace | `FlowsWorkspace.tsx` `useFlowsLive(refresh, true)` + `useCallback(..., [])` |
| Auth must not change | `AuthProvider.tsx`, `storage.ts` `assertNoTokenStorage` |
| Nav already Flows / Status / Audit / Reset | `forbidden.ts` `navItems` |
| Old paper/navy/Segoe | `f6f38a6` `styles.css`: `color-scheme: light`, `#eef2f4`, `#fffdf8`, `#16324f`, `"Segoe UI"` |

## Design

### 1. Shared CSS — one look (no leftover paper/navy/Segoe)

Stay on existing tokens. Do **not** reintroduce `#eef2f4`, `#fffdf8`, `#16324f`, `color-scheme: light`, or `Segoe UI`.

Add / tighten in `web/src/styles.css` only:

1. **`:root` font stack** include IBM Plex Mono (plan leftover from #67): `"IBM Plex Sans", "IBM Plex Mono", ui-sans-serif, sans-serif`.
2. **`.page`**: still max-width document; add comfortable gap. Optional `.page-head` for kicker + `h1` (inspector-head density: `h1` ~1.15–1.35rem, kicker uppercase muted like `.kicker`).
3. **`.panel`**: background `var(--panel)` (`#181a1f`), border `var(--line)`, radius ~0.4rem, padding. Use for Status CA/store/features table, Audit table, Login/Reset forms, revisions `<pre class="raw">` already panel-like.
4. **Buttons (global)** so UA paper buttons die:
   - Default `button`: panel bg, fg, line border, radius, padding (match Sign out / mock chips).
   - Keep more-specific `.tabs button` (transparent + accent underline), `.linkish` (fg outline), `.btn-danger` (muted red), `button[type="submit"]` / `.primary` (accent `#6ea8d1` / `#0b0c0e`).
   - Do **not** set `--accent` as a full-page fill (old navy topbar bug).
5. **`code`**: IBM Plex Mono, muted panel chip (not white paper).
6. **Checkboxes / `role="switch"`**: `accent-color: var(--accent)` so Status toggles and Reset confirm are not light-theme UA.
7. **Autofill**: `color-scheme: dark` already; add `input:-webkit-autofill` box-shadow fill `var(--panel)` so Login token field cannot flash white.
8. **Banners / empty / loading**: `.banner-error` / `.banner-warn` / `[role=status]` readable on `#0b0c0e` (existing err/warn tokens). Empty copy uses `.muted`.
9. **`table.data`**: sit on `var(--panel)` (today `--card` = elev `#121317`). Header row muted. Keep collapse + line borders.
10. **Regression lock in CSS comments + tests**: file must not contain `Segoe`, `#eef2f4`, `#fffdf8`, `#16324f`.

No new CSS framework. No inline `style={{ color: ... }}` on pages.

### 2. Markup class hooks only (same behavior)

**Do not** change fetch, apply, reset, login, or listAudit logic. Class / wrapper / heading density only.

| Page | Markup |
|---|---|
| Status | `<p className="kicker">Status</p>` above existing `<h1>Status</h1>`. Wrap CA `dl`, store `dl`, listeners, features table, revisions in `.panel`. Keep every existing string: lab CA warning, Ready/Intercept prose (`Ready: yes/no · Intercept: on/off`), download link, feature table headers, `Reset required`, `change via REST/MCP`. **Intercept honesty:** keep that prose. Do **not** add an `intercepted` or `tunnel-not-decrypt` chip on Status (those words are flow-inspector chips). Never import `isTunnelNotDecrypt`. Error/loading `<main className="page">` stay; no extra fetch. |
| Audit | Kicker + `h1` Audit. Empty: `<p className="muted">No audit events.</p>`. Table in `.panel`. Same columns. |
| Reset | Kicker + existing `h1` / phrase / `RESET` `<code>` / checkbox label. Form in `.panel`. Submit stays `type="submit"` (accent). Disabled until `canSubmitReset`. |
| Login | Kicker optional; keep `h1` “Sign in to LabMITM”. Form in `.panel`. Bearer field + Sign in. No live / `:443` chips on signed-out header (not signed-in chrome). |
| App loading | `Checking session…` may use `.page` + `.muted`; no new routes. |

`Shell`, skip-link `#app-main`, sidenav, Flows workspace, `useFlowsLive` **unchanged**.

### 3. Intercept vs tunnel chips stay honest

- Header **live** / **:443 intercept only**: signed-in only; overlay copy (`docs/known-limitations.md`).
- Flow list / inspector: existing `chip-accent` intercepted + `chip-tunnel` tunnel-not-decrypt (`FlowInspector.tsx`, `flowKind.ts`).
- Status `status.intercept` is a **boolean** (`web/src/api/types.ts`), not a CONNECT classification. Do not import `flowKind` into Status/Audit/Reset/Login.

### 4. Auth / XSS (must not regress)

- Cookie session + memory CSRF.
- `assertNoTokenStorage`.
- `security.test.ts`: no `dangerouslySetInnerHTML`, no `.innerHTML =`, no forbidden labels, download attachments stay on `FlowInspector.tsx`.
- Login remains bearer-only.

### 5. Tests (fail before / pass after)

| File | What |
|---|---|
| `web/src/ui/chrome.test.ts` (new) | Read `styles.css` as text: must contain `#0b0c0e`, `#121317`, `#181a1f`, `#ecece8`, `#6ea8d1`, `#c4a35a`, `IBM Plex`; must **not** contain `Segoe`, `#eef2f4`, `#fffdf8`, `#16324f`, `color-scheme: light`. Extract the unadorned `button { ... }` rule (not `button[type="submit"]`) and require `background` inside it. **Fails today** (`styles.css` 280–283 is font/cursor only; submit already has `background`). Also read `LoginPage.tsx`, `StatusPage.tsx`, `AuditPage.tsx`, `ResetPage.tsx` and require `className` includes `panel` (and a `kicker` on Status/Audit/Reset). **Fails today** — none of those files contain `panel`. This pins **page bodies**, not Shell. |
| `web/src/pages/AuditPage.test.tsx` (new) | Stub `GET /v1/audit` as `{ events: [] }` and as `{ events: [{ id, time, capability, actorId, result }] }` (`AuditList` in `types.ts` 250–252 — **not** `items`). Empty + one-row + no fuzzer. **Fails today** (file missing). |
| `web/src/App.test.tsx` | Extend (or add cases): `AppRoutes` at `/status`, `/audit`, `/reset` with **signed-in** `sessionView()` — skip-link, LabMITM, live + `:443 intercept only`, Sign out, **nav labels** Flows/Status/Audit/Reset, active nav on that route, **no** `tunnel-not-decrypt` / `intercepted` chip text on those pages. Stub `GET /v1/status`, `GET /v1/features`, `GET /v1/audit` (`{ events: [] }`). **`/login` must 401 `GET /v1/session`** (do not seed `sessionView()` — `RedirectIfSignedIn` in `App.tsx` 102–104 sends signed-in users to `/`). Assert LabMITM, bearer field, **no** Sign out, **no** live / `:443 intercept only`, **no** tunnel-not-decrypt. |
| `StatusPage.test.tsx` / `ResetPage.test.tsx` / `LoginPage.test.tsx` | Re-run unchanged behavior assertions. Add only chrome-safe queries (`kicker` / panel optional). Do not weaken setFeature / RESET / storage tests. |
| `FlowsPage.test.tsx` / `useFlowsLive.test.ts` | Re-run: SSE still one EventSource on select. |
| `security.test.ts` | Keep XSS/storage/forbidden scans. |

jsdom does not prove pixels. Do **not** assert `getComputedStyle` (often empty). Pin tokens + class hooks + roles.

Do not delete existing assertions.

### 6. Docs (same change)

Update **Last reviewed** on touched numbered docs:

- `docs/01-architecture.md` Embedded operator UI: Status / Audit / Reset / Login share Flows dark chrome (IBM Plex, tokens); tunnel-not-decrypt remains a flow chip only.
- `docs/08-rest-api.md` Embedded operator UI table: same sentence.
- `docs/12-testing-strategy.md` UI row: remaining-page chrome + Audit test + token/Segoe lock.
- `web/README.md` Pages: remaining pages share dark chrome.
- `CHANGELOG.md` Unreleased **Changed**: fold remaining-page chrome into the existing operator SPA sentence (do not invent a second Unreleased story).
- No ADR. Cross-links stay absolute HTTPS.

### 7. Embed / CI

1. `make web-test`
2. `make web-build` (embed `internal/web/dist`)
3. `make test-docs` / `make test-changelog` if docs/changelog change
4. No `make generate`
5. `spa_test.go` still sees `LabMITM` on `GET /` and `GET /flows/01JTEST`

### 8. Implementation order

1. CSS primitives (button, panel, code, autofill, checkbox, table, font stack).
2. Class hooks on Status / Audit / Reset / Login only.
3. Tests (chrome lock, Audit, App routes).
4. Docs + CHANGELOG.
5. `make web-test` then `make web-build`.
6. Commit + push on `cursor/flows-split-pane-e0eb`. Update PR #67. Do not merge.

### 9. Risks

| Risk | Mitigation |
|---|---|
| Global `button` restyle breaks tab underline | `.tabs button` already overrides; keep it more specific |
| Status tests query `getAllByText("live")` | Feature applyMode `live` plus header chip — if chrome test mounts Shell + Status, count may rise. **Do not** mount `AppRoutes` inside existing `StatusPage` tests (they render `<StatusPage />` alone — header chips absent). App chrome test uses `getByText(":443 intercept only")` and nav, not `getAllByText("live")` loosely |
| `status.intercept` mistaken for tunnel | No `flowKind` import on remaining pages; App test asserts no tunnel-not-decrypt string on those routes |
| SSE remount when visiting Status | Expected: leaving Flows unmounts workspace. Returning remounts. Do not move ES to Shell |
| Autofill CSS ignored in some engines | Best-effort; `color-scheme: dark` is the contract |

## Out of repo

Do not touch other repositories.

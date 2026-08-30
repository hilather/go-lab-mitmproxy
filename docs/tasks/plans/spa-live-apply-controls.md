# Plan: Operator SPA live-apply controls (Status / inspector)

Status: BLOCKED (skeptic-plan-review sweep 3 still had BLOCKING findings; cap 3). Do not implement on this revision. Folds below are the would-be contract for a later ACCEPT.
Owners: Operator UI
Last reviewed: 2026-08-30
Branch: `cursor/spa-live-apply-controls-bb9c`
Do not merge. Do not touch mcp-integration-lab, labgraph, or #12.
Origin `agent-skills` clone was unavailable on this VM; skeptic templates run from the follow-up prompt.

This document is an implementation contract. Investigate-first. Claims below were verified in this tree (not the inspected-gap list).

## Verdict (planning)

The v1.5.0 operator SPA lists hop/accept `setFeature` rows and disables `ui.enabled`. It does **not** expose the other live apply verbs, does **not** render compact `status.features` (including additive `httpAuth` and Reset-only 1.2 flags), hardcodes header **:443 intercept only**, and does not badge `frames[].action`.

**Scope:** SPA + docs + ADR 0018 (Status `ui.enabled` reconsideration). No new capability IDs. Catalog stays 31. `features.get` stays 11. No Python mitmproxy. No `third_party/` edits. Do not invert ADR 0013 live vs Reset. Do not invert D22-carve (websocket/connect/absoluteForm stay default-on hop gates).

## Problem (verified)

| Gap | Evidence | Contract |
|---|---|---|
| `StatusFeatures` omits `httpAuth` | `web/src/api/types.ts` 167–182 vs `internal/control/rest/dto.go` `statusFeaturesJSON.HTTPAuth` line 85 | ADR 0017 K10 reopen; compact boolean on `GET /v1/status` |
| Status never renders `status.features` | `StatusPage.tsx` 136–288: Ready/Intercept prose, CA, store, listeners, `GET /v1/features` table, revisions. No compact-features panel | 1.2 nested flags + `httpAuth` live on status JSON today (`featuresFromSpec` `dto.go` 564–585) |
| No `replaceHTTPAuth` control | `ChangeOperation` is `op` + optional `feature` only (`types.ts` 216–219). `applyChanges` posts that body | 8th `KnownOp` (`internal/model/operation.go` 12, 34). Body is `httpAuth` (`enabled` + `realm` + file-ref `users[]`). **Not** a `setFeature` ID (ADR 0017) |
| `ui.enabled` Status toggle disabled | `StatusPage.tsx` 10–17 `featureToggleable` excludes `FEATURE_UI_ENABLED`. Copy: “change via REST/MCP” | API **does** allow live `setFeature` (`docs/06` table; ADR 0013 ID switch). Closed product call #3: **no Status toggle** (404s SPA). Review trigger is this reconsideration |
| No `replaceTLS` / ports editor | Status shows `status.intercept` boolean only. `statusResponse` has no `tls.ports` (`dto.go` 43–51) | Live verb is `replaceTLS` with full `tls` object. `setFeature` of `tls.intercept` is `validation_failed` |
| Shell hardcodes `:443` | `App.tsx` 55; `App.test.tsx` 81; `flowKind.ts` `TUNNEL_REASON` / `FLOWS_FOOTER` | Overlay default is `ports: [443]` (`examples/labmitm.yaml` 72). Live ports live on `GET /v1/state` `canonical.spec.tls.ports`, **not** `GET /v1/status` |
| No `replaceRules` / `replaceAdmission` / `replaceCompat` prefix editor | Features table toggles `rules.enabled` and `compat.flowREST` via `setFeature` only | `replaceRules` is full subtree. `replaceAdmission` is full `admission` (durations as Go strings). `compat.flowREST.pathPrefix` is `replaceCompat` only |
| Frames tab no drop/block | `WebSocketFrame` in `types.ts` 51–61 has no `action`. `FramesPanel` (`FlowInspector.tsx` 150–157) prints direction/opcode/close/truncated/masked | GET-by-id `frames[].action` is `drop` / `block`; omitted when forwarded (`dto.go` 249 `json:"action,omitempty"`; ADR 0015 D73) |
| Reset-only 1.2 knobs invisible as such | Catalog has one reset row (`listeners.originalDestination`). Compact 1.2 booleans exist on `status.features` but Status never renders them | ADR 0013: 1.2 nested flags + orig-dest **address** + listener **addresses** stay Reset-only. Do not offer live toggles |

## Non-goals

- New `/v1` paths, catalog rows, MCP tools, or `setFeature` IDs (`proxy.httpAuth`, 1.2 nested flags, `tls.intercept`).
- Inventing `tls.ports` on `GET /v1/status` / MCP `statusFeaturesJSON` (would be a REST+MCP lockstep field invention). Live ports come from existing `state.get`.
- Live toggles for Reset-only flags (`inspectFrames`, BIND/UDP/user-pass, orig-dest bind, listener addresses, h2 nested flags).
- Inverting D22-carve defaults or hop-gate 403 behavior.
- Visual mitmweb rule builder, fuzzer, repeater, exploit, SSL-strip, Relay.
- Interpolating `TUNNEL_REASON` / Flows footer (stay overlay residual; tests pin `tls.ports:[443]`). Header chip **does** become live.
- `replaceTargets` / `replaceStoreCaps` editors (live verbs, not in the requested knob list). Report as remaining UI gaps.
- Editing `third_party/`, mcp-integration-lab, labgraph, or Helm merge.
- Collecting HTTP-auth or SOCKS passwords in the SPA (file refs only; Canonical never contains secrets).

## Evidence (verified)

| Claim | Evidence |
|---|---|
| `GET /v1/status` has no ports | `statusResponse` (`dto.go` 43–51): ready, revisions, listeners, store, intercept, ca, features |
| Status handler already loads Canonical | `handleStatus` (`handlers.go` 116–150) fills listeners + `featuresFromSpec` from `GetState` |
| `GET /v1/state` is the live spec | Capability `state.get` (`docs/07`); `stateViewJSON.canonical` is the redacted State (`apiVersion`/`kind`/`metadata`/`spec`). `marshalAPI` → `FormatWireTree` (duration + IEC byte strings) |
| Apply decodes duration strings | `decodeBytes` → `config.CoerceWireTree` (`request.go` 74–76) |
| `replaceTLS` is full subtree | `Operation.TLS *TLSSpec` (`operation.go` 29). Fields: intercept, hosts, ports, ca, upstream (`spec.go` 151–157). Generate-mode CA rotates when TLS spec changes |
| Empty ports materialize `[443]` | `normalize.go` 84–86; `docs/06` “After normalize, empty → `[443]`”. Validate only checks 1–65535. `GET /v1/state` never returns empty ports after a successful apply |
| HTTP auth users are file refs | `UserPassUserSpec`: `id`, `usernameFile`, `passwordFile` (`spec.go` 83–87). Export contract forbids leaking password bytes |
| `ui.enabled` live from REST/MCP | ADR 0013 ID switch + `docs/06` line 257. Status exclusion is UX (`StatusPage.tsx` 11 comment) |
| Frame action on GET-by-id | `webSocketFrameJSON.Action` omitempty; contract `TestContractWebSocketFrameAction` (`contract_test.go` 580–584) |
| SPA has no `getState` | `client.ts` has `getStatus`, `getFeatures`, `applyChanges`, `resetState` only |

## Design

### 0. ADR 0018 — Status may apply `ui.enabled` (gated)

ADR 0013 closed product call #3 and the review trigger: *“when Status toggling `ui.enabled` is reconsidered.”* The API already allows live `setFeature`. This workstream is that reconsideration.

**D77 — Status may apply `ui.enabled` via the existing `setFeature` verb after a gated confirm.** Disabling 404s `/` on the next UI request and leaves REST/MCP up. Recovery is REST/MCP `setFeature` `ui.enabled: true` or bootstrap YAML + Reset. This does **not** change apply mode (still live). It does **not** make Reset-only IDs live.

Confirm UX (match existing `window.confirm` on Flows delete; no new modal kit):

1. Confirm **only when turning off** (`enabled: true` → `false`). Turning on is a normal `setFeature` with no confirm.
2. Off-confirm text must say **all inspector routes** (`/`, `/status`, `/flows/…`) 404. `tryUI` declines when UI is disabled (`spa.go` 15–17); `server.go` writes `404` `not_found`. Recovery is REST/MCP `setFeature ui.enabled: true` (or bootstrap + Reset).
3. Cancel → no POST.
4. OK → same `applyChanges` path as other `setFeature` rows (OCC, new UUID idempotency key, optional reason).

Register D77 in the docs/01 decision table (next to D76), `docs/README.md` ADR list, and `scripts/checkdocs/main.go` `RequiredRootDocs` (today ends at `0017-http-proxy-407.md`). Add 0018 to **Related ADRs** on every numbered doc this change touches. Update ADR 0013 closed call #3 / docs/06 / known-limitations in the same change. Do not write a second Status exception for `httpAuth` (that stays `replaceHTTPAuth`). Note on ADR 0017’s review trigger that Status exposes `replaceHTTPAuth` (not a Features-table `setFeature` switch).

### 1. Client types and `getState`

`web/src/api/types.ts`:

- Add `httpAuth: boolean` to `StatusFeatures` (required; backend always emits it).
- Add `action?: string` to `WebSocketFrame`.
- Expand `ChangeOperation` with optional `tls` (`TLSSpec`), `rules` (`RulesSpec`), `admission` (`AdmissionSpec`), `compat` (`CompatSpec` = `{ flowREST: { enabled, pathPrefix } }`), `httpAuth` (`HTTPAuthSpec`) — typed; no `any`. **`compat` is nested.** A flat `{enabled, pathPrefix}` under `compat` unmarshals to a zero `FlowREST` and disables `/compat` (`spec.go` 235–245; `operations.go` 59–64).
- Add `StateView` + nested spec slices that match the wire document: `canonical.spec.tls`, `canonical.spec.rules`, `canonical.spec.compat.flowREST`, `canonical.spec.listeners`, `canonical.spec.protocols`, and **`canonical.spec.proxy.{admission,httpAuth}`** (not spec siblings). Durations and byte sizes are **strings** on the wire (`"10m"`, `"64MiB"`).

`web/src/api/client.ts`:

- `getState(): Promise<StateView>` → `GET /v1/state` via `apiFetch` (cookie + CSRF not required for GET).

Do not add a parallel `/v1/status` `tls.ports` field.

### 2. Live spec context + Shell chip (`GET /v1/state`, not `GET /v1/status`)

**Verified deviation from the request wording.** The request asked for ports from live `GET /v1/status`. This tree’s `statusResponse` has no `tls` / `ports` field (`dto.go` 43–51). Adding one would invent a REST+MCP compact field (K10-class lockstep) without an ADR. Existing `state.get` already returns `canonical.spec.tls.ports`. Do **not** invent `status.tls.ports`.

`App.tsx`: the chip lives in `Shell` (parent of `RequireSession` — `App.tsx` 52–55, 115–127). Mount `LiveSpecProvider` **inside `Shell` when `signedIn`**. **Do not call `useLiveSpec()` in `Shell` itself** (that hook would sit outside the provider). Extract `InterceptChip` (or `SignedInChrome`) as a **child** of the provider; only that child reads context. Do **not** fetch `getState` while signed out.

- Default context (no provider / tests that mount `<StatusPage />` alone): `{ state: null, refresh: async () => {}, error: "" }` so `useLiveSpec()` never throws.
- When mounted (signed-in Shell): fetch `getState()` on mount. Expose `{ state, refresh, error }`.
- Status apply success **and** 409 refetch: `getStatus()` + `setStatus` **and** `refreshFeatures()` + `getState()` + provider `refresh()`. Catch getState/getStatus failures on 409 so the apply problem+json detail still shows. `replaceTLS` rotates generate-mode CA (`status.ca`); `replaceHTTPAuth` flips compact `status.features.httpAuth` — those come from `GET /v1/status`, not from features/state alone.
- Chip text (signed-in only): `:{ports joined} intercept` when `spec.tls.intercept` is true (e.g. `:443 intercept` or `:443,:8443 intercept`). Intercept off: `intercept off`. Fetch error / no state yet: `intercept ports unknown`. **Never** fall back to hardcoded `:443 intercept only`. **No “intercept ports empty” state** — normalize rewrites empty ports to `[443]` (`normalize.go` 84–86).
- Keep the **live** chip.
- `TUNNEL_REASON` and `FLOWS_FOOTER` stay overlay copy (`tls.ports:[443]`). Document as residual.

`GET /v1/state` failure must **not** replace the existing Status CA/store/features UI. Panel-level error only. **Forms no-op** until `canonical.spec.tls` / `proxy.admission` / `proxy.httpAuth` / `rules` / `compat.flowREST` exist (unguarded `.admission` throws).

**Shared `sampleState()`** (used by `stubPageFetch`, the 409 mock, and App `/status`): full wire document — `runtimeRevision`, `canonical.spec.tls` (ports **and** `hosts`/`ca`/`upstream`), `canonical.spec.proxy.admission`, `canonical.spec.proxy.httpAuth`, `canonical.spec.rules`, `canonical.spec.compat.flowREST`, `canonical.spec.listeners.originalDestination`. Flows-only chrome may stub ports+intercept only. App `/status` **must** use `sampleState()`, not a ports-only body.

**Test stubs:** `stubPageFetch` **and** the inline 409 fetch mock **and** both `App.test.tsx` signed-in stubs must answer `GET /v1/state`. Login remains 401-only and must not call `getState`.

`web/src/ui/chrome.test.ts` forbids the string `tunnel-not-decrypt` on Status markup. New panels must not use that token.

### 3. Status page sections (same chrome: `.panel`, `.field`, `.data`, switches)

Keep existing CA / store / listeners / `GET /v1/features` table / revisions. Add:

**A. Compact runtime flags (`status.features`)** — read-only badges, two groups:

1. **Live-applyable (not catalog rows):** `httpAuth` — badge + pointer to the HTTP 407 panel. Do **not** add a boolean `setFeature` switch.
2. **Reset-required (1.2 + bind):** `http2ClientCleartext`, `http2Origin`, `http2ExtendedConnect`, `http2CapturePush`, `http2GRPCDecode`, `inspectWebSocketFrames`, `acceptBind`, `acceptUDPAssociate`, `acceptUserPass`, `originalDestination` (enabled from compact status). Each row: on/off badge + muted text `Reset required` (**not** a second `<Link to="/reset">`). The catalog table keeps the **single** existing `Reset required` link (`StatusPage.test.tsx` 141–142 `getByRole` is one match). Listeners panel: existing bound addresses + muted “bootstrap + Reset only”. Also show orig-dest **address** from `getState()` when non-empty; if disabled and address is `""` (normalize fills `127.0.0.1:8890` only when enabled — `normalize.go` 54–55), muted “unset until enabled (normalize default `127.0.0.1:8890`)”. One muted `metrics.listen` line from `canonical.spec.observability.metrics.listen` (Reset-only address; `docs/06` 265). No switches.

**B. Features table (existing):** keep hop/accept `setFeature` toggles. **Enable** `ui.enabled` for admins via `featureToggleable` (drop the exclusion) + gated confirm. Keep **no** switch for `tls.intercept` (`verb === "replaceTLS"`). Keep no switch for `applyMode === "reset"`. D22-carve rows (`protocols.websocket` / `connect` / `absoluteForm`) stay live toggles defaulting on in fixtures.

**C. Live TLS (`replaceTLS`):** load `canonical.spec.tls` from `getState()`. Admin form: intercept checkbox, ports text (`443,8443` → `number[]`, each 1–65535). **Reject a blank ports field client-side** (do not POST `ports: []` — normalize would silently become `[443]`). Hidden/passthrough: current `hosts`, `ca`, `upstream` so the POST is a full subtree. Submit posts `{ op: "replaceTLS", tls: <full> }` with `expectedRevision` from `getState().runtimeRevision`. Banner: generate-mode CA rotates when the TLS spec changes. After success **and** 409: refresh status + features + state + provider.

**D. Live HTTP 407 (`replaceHTTPAuth`):** load `canonical.spec.proxy.httpAuth`. Admin form: enabled checkbox, realm input, users as a JSON textarea of `{id, usernameFile, passwordFile}[]` (parse; never a password field). When `enabled` is true, require `users.length >= 1` before POST (`validate.go` 347–352). Submit full `httpAuth` object. Show compact `status.features.httpAuth` next to the heading. Viewers: read-only.

**E. Live rules (`replaceRules`):** load `canonical.spec.rules`. Items JSON textarea (server validates; SPA does not invent match/action schemas). Invalid JSON is a client banner, no POST. At **submit time**, `enabled` comes from a fresh `getFeatures()` catalog row `rules.enabled` (or freshly fetched `canonical.spec.rules.enabled`), **not** from form state captured on first load — otherwise a catalog toggle then a stale items-save undoes `enabled` (`operations.go` 47–52 assigns the full subtree). Empty items + enabled false is stock capture.

**F. Live admission (`replaceAdmission`):** load `canonical.spec.proxy.admission`. Admin fields for every key. Timeouts stay Go duration strings (`10m`). **`maxInFlightBytes` stays an IEC string** (`64MiB`) — do not `Number()` it. POST the full object. Note: `http.Server.IdleTimeout` stays Start-time (docs/06).

**G. Live compat prefix (`replaceCompat`):** load `canonical.spec.compat.flowREST`. Admin: `pathPrefix` input. POST **`{ op: "replaceCompat", compat: { flowREST: { enabled, pathPrefix } } }`** — never a flat `compat` object. At submit, `enabled` from fresh catalog row `compat.flowREST` / fresh state (same stale-enabled rule as 3E). Collision with restPath/mcpPath is server `validation_failed`.

Shared apply helper (extract from `onToggle`): OCC `expectedRevision` from **fresh** `getState().runtimeRevision` immediately before POST (same value as `features.runtimeRevision` in production). New `crypto.randomUUID()` per attempt, optional reason, CSRF via `apiFetch`. One `busyRef`. Viewers: no forms. After **every** successful apply **and** on 409: `getStatus` + `getFeatures` + `getState` + provider refresh so CA / intercept / compact `httpAuth` / subtree `enabled` cannot stay stale. Keep the apply problem+json detail if a refresh fails.

### 4. Frames tab badge

`FramesPanel`: if `fr.action === "drop"` or `"block"`, render `<span className="badge">` with that token next to direction/opcode. Other/empty: no badge (forwarded). Escaped text unchanged. No new forbidden labels.

### 5. Tests (fail before / pass after)

Do not delete or weaken existing assertions except the ones this behavior change replaces (`no Toggle ui.enabled`, `/change via REST\/MCP/` next to that row — drop that muted line when the gated switch lands, `StatusPage.test.tsx` 145–152), hardcoded `:443`). Extend `sampleStatus().features` (and App `/status` status JSON) with `httpAuth` plus every compact 1.2 boolean the reset-required panel renders.

| File | What |
|---|---|
| `web/src/api/client.test.ts` | `getState` GETs `/v1/state`; `applyChanges` serializes `replaceTLS` / `replaceHTTPAuth` / `replaceRules` / `replaceAdmission` / `replaceCompat` bodies. **`replaceCompat` assertion requires `compat.flowREST` nest** |
| `web/src/pages/StatusPage.test.tsx` | Stub `GET /v1/state` in `stubPageFetch` **and** the inline 409 mock. **409 OCC:** return `sha256:abc` for **every** `/v1/state` **until after the 409 apply response**; switch to `sha256:newer` only on the post-409 generation (tie to the features refetch, **not** a `stateGets` counter). Mount + pre-POST OCC must still send `expectedRevision: "sha256:abc"` (`StatusPage.test.tsx` 221). `stubPageFetch` defaults `runtimeRevision` to the catalog’s `sha256:abc`. `replaceRules` / `replaceCompat` “fresh enabled” `getFeatures()` must **not** share the 409 `featureGets` incrementor. Assert: `httpAuth` compact badge; compact reset-required **text** (still exactly **one** `Reset required` **link** — catalog row); no switches on 1.2 ids; `replaceTLS` posts full tls including unchanged `ca` and **rejects blank ports** (no POST); ports `443,8443`; after `replaceTLS`, CA/intercept come from a **refetched** `GET /v1/status`; `replaceHTTPAuth` posts file-ref users (no password bytes) and refuses enabled+empty users; invalid users JSON is a client banner (no POST); `replaceRules` posts items JSON with `enabled` from the latest catalog row; `replaceAdmission` posts **every** admission field from the stub (durations + `maxInFlightBytes` IEC string + `maxConcurrentStreams`); `replaceCompat` posts `{ compat: { flowREST: { enabled, pathPrefix } } }` without flipping enabled; `ui.enabled` switch exists for admin; confirm runs **only on turn-off** (`vi.spyOn(window, "confirm")`); confirm-cancel posts nothing; confirm-ok posts `setFeature`; viewer still has no switches/forms; 409 refetch still unique idempotency keys; D22 rows still toggleable; keep `getByRole("link", { name: /Reset required/i })` as a single match; no fuzzer labels |
| `web/src/App.test.tsx` | Flows chrome may stub ports+intercept only (`[8443]`, intercept true). The `/status` `/audit` `/reset` loop **must** stub `sampleState()` (full subtrees) so Status forms do not throw. Assert `:8443 intercept` and **absence** of `:443 intercept only`. Login (line 198) still has no intercept chip and does not fetch state |
| `web/src/pages/FlowPage.test.tsx` | Frames fixture with `action: "drop"` and `action: "block"` shows those badges; forwarded frame (no action) does not |
| `web/src/pages/StatusPage.test.tsx` existing setFeature / 409 / CA tests | Keep; extend stub to answer `GET /v1/state` |

jsdom does not prove pixels. Pin roles, POST bodies, and visible tokens.

### 6. Docs (same change)

Update **Last reviewed** on touched numbered docs. Cross-links stay absolute HTTPS.

- `docs/adr/0018-status-ui-enabled-apply.md` (new): D77 as above.
- `docs/adr/0013-live-protocol-feature-gates.md`: closed call #3 + Status sentence point at 0018; live vs Reset table unchanged.
- `docs/01-architecture.md` Key decisions: add **D77** row. Disambiguate D1’s “TacLab is the frozen exception (ADR 0018)” as **TacLab** ADR 0018 (cross-repo) so it does not look like this file. Embedded operator UI Pages: live apply panels; chip is live `GET /v1/state` ports; Frames badges; `ui.enabled` gated off-confirm.
- `docs/03-tls-interception.md`: chip/ports sentence — live ports from state; tunnel reason still default overlay copy.
- `docs/06-state-and-configuration.md`: `ui.enabled` row — Status gated `setFeature` (0018). Fix the `replaceCompat` apply-verb row to the nested `{ flowREST: { enabled, pathPrefix } }` object (line 237 is flat today).
- `docs/07-control-plane-and-parity.md`: Related ADRs +0018. Compact `status.features` already listed — note the SPA now **renders** those booleans. **Do not invent a Pages table** (that table lives in docs/01 and docs/08).
- `docs/08-rest-api.md`: operator UI Pages row; compact `httpAuth`; gated `ui.enabled`; no new capabilities.
- `docs/12-testing-strategy.md`: Feature gates + UI rows (Status live verbs; `ui.enabled` gated off-confirm; Frames action badges). Related ADRs +0018.
- `docs/README.md` ADR index + `scripts/checkdocs/main.go` `RequiredRootDocs`: add `docs/adr/0018-status-ui-enabled-apply.md`.
- `docs/adr/0017-http-proxy-407.md` review trigger: Status `replaceHTTPAuth` panel landed (not a `setFeature` Features-table switch).
- `docs/known-limitations.md`: remove “No Status toggle for `ui.enabled`” on **both** the D51' residual (~line 31) **and** the chrome residual (~139–140). **Split** line 139 (live chip vs overlay footer/`TUNNEL_REASON`). Remove the Frames no-badge / “until a UI follow-on” clause. Residual: no `replaceTargets`/`replaceStoreCaps` SPA editors.
- `docs/10-security-architecture.md`: one sentence — Status may gate-off `ui.enabled`; next inspector request 404s; recovery is REST/MCP. Last reviewed bump.
- `web/README.md`: live chip + Status apply panels.
- `CHANGELOG.md` Unreleased **Added**: Status live-apply panels, live intercept-ports chip, Frames drop/block badges, compact reset-required flags, gated `ui.enabled`.

No OpenAPI / generate unless a Go DTO changes (it should not).

### 7. Embed / CI

1. `make format` / `make lint` if Go/docs touch checkdocs
2. `make web-test`
3. `make web-build` (embed `internal/web/dist`)
4. `make test-docs` / `make test-changelog`
5. After embed: `go test ./internal/control/rest -run SPA` (or `make test` if time allows) so `spa_test.go` still sees `LabMITM` on `GET /`
6. No `make generate` if Go/OpenAPI untouched
7. No browser tools in this VM — say so in the PR; jsdom + `spa_test.go` are the verification substitute

PR last line: **Mud Turtle**. Do not merge.

### 8. Implementation order

1. Failing tests first (`StatusPage` / `App` / `FlowPage` / `client`) that pin the new contracts.
2. ADR 0018 + checkdocs/README/docs/01 D77 registration + types/`getState` + apply operation shapes (`compat.flowREST` nest).
3. Frames badge.
4. `LiveSpecProvider` (default no-op; mount **inside signed-in `Shell`** so the chip is a consumer) + live ports chip.
5. Status compact features + reset-required **text** (one catalog link).
6. Shared apply helper; `ui.enabled` gated **off** confirm.
7. replaceTLS / replaceHTTPAuth / replaceRules / replaceAdmission / replaceCompat forms.
8. Docs/CHANGELOG.
9. `make format` / `make lint` / `make web-test` / `make web-build` / `make test-docs` / `make test-changelog`.
10. Commit + push including **`internal/web/dist`** (`make web-build` output; `web/dist` is gitignored, `internal/web/dist` is tracked). Open draft PR. Last line **Mud Turtle**. Do not merge.

### 9. Risks

| Risk | Mitigation |
|---|---|
| `replaceTLS` / `replaceRules` / `replaceAdmission` partial body wipes sibling fields | Always GET state, merge the edited fields, POST the full subtree |
| Duration/byte fields as numbers fail validate | Keep wire strings from `getState`; inputs stay strings (`10m`, `64MiB`). Assert `maxInFlightBytes` is a string in the apply body |
| Empty `tls.ports` silently become `[443]` | Reject blank ports; no empty-ports chip |
| Stale `enabled` on subtree replace | Refresh state+features after every apply; read `enabled` at submit from fresh catalog/state |
| Flat `replaceCompat` disables `/compat` | POST `{ compat: { flowREST: { … } } }` only |
| `LiveSpecProvider` throws in Status-only tests / fetches on login / chip not a consumer | Default no-op context; mount inside **signed-in `Shell`** (chip + Outlet); no fetch on `/login`; stub `/v1/state` in every Status/App signed-in mock |
| Stale Status CA / intercept / `httpAuth` after apply | Shared helper always `getStatus()` + `setStatus` |
| `ui.enabled` off 404s the SPA | Gated confirm; ADR 0018; docs recovery path |
| Inventing `tls.ports` on status | Do not. Chip and TLS panel use `GET /v1/state` |
| `setFeature` of `tls.intercept` or `proxy.httpAuth` | Never send those IDs. TLS uses `replaceTLS`. 407 uses `replaceHTTPAuth` |
| D22-carve inverted | Do not change catalog defaults or disable websocket/connect/absoluteForm toggles |
| Header chip tests vs Status `getAllByText("live")` | Status tests render `<StatusPage />` without Shell (existing). App tests stub state |
| Secrets in HTTP auth form | File paths only; assert POST body has no password material |
| OCC races between features revision and state revision | Use `getState().runtimeRevision` for all apply ops; refresh both after success/409 |

## Remaining UI gaps (after this change)

- `replaceTargets` / `replaceStoreCaps` have no Status editor.
- `TUNNEL_REASON` / Flows footer stay overlay `tls.ports:[443]`.
- No live `GET /v1/status` `tls.ports` field (by design; `state.get` is the spec).
- No visual rule builder (JSON items only).
- Reset-only knobs remain Reset-only (visible, not toggled).
- **This workstream did not implement** (plan review BLOCKED after 3 skeptic sweeps). All listed live-apply Status controls remain missing on `main`.

## Review-plan (first-party)

Sweep 0: checked claims against `web/src/**`, `internal/control/rest/dto.go`, `internal/model/operation.go`, ADR 0013/0015/0017, `App.test.tsx`, `chrome.test.ts`. Folded LiveSpec context; no invented `status.tls.ports`.

## Skeptic-plan-review sweep 1 (fresh)

**Verdict: REVISE** (5 BLOCKING). Folded into this revision:

1. Empty `tls.ports` normalize to `[443]` — drop empty-ports chip; reject blank ports.
2. Compact reset rows must not add more `Reset required` **links** (`getByRole` single match).
3. `replaceCompat` body is `{ compat: { flowREST: { enabled, pathPrefix } } }`.
4. `LiveSpecProvider` default no-op; mount under `RequireSession`; stub `/v1/state` in stubPageFetch + 409 mock + App signed-in stubs.
5. Refresh state+features after every apply; read subtree `enabled` at submit from fresh catalog/state.

Also folded NON-BLOCKING: D77/0018 registration (docs/01, README, checkdocs); docs/07 has no Pages table; httpAuth enabled needs users; confirm only on turn-off; ADR 0017 review-trigger note; `maxInFlightBytes` string; Mud Turtle + format/lint + tests first.

## Skeptic-plan-review sweep 2 (fresh)

**Verdict: REVISE** (3 BLOCKING). Folded into this revision:

1. Chip is in `Shell` (parent of `RequireSession`) — provider must wrap signed-in Shell header+Outlet, not only `RequireSession`.
2. Shared helper must `getStatus()` after apply/409 (`replaceTLS` rotates CA; `replaceHTTPAuth` flips compact badge).
3. 409 mock must bump `state.runtimeRevision` in lockstep with the catalog so OCC still asserts `sha256:newer`.

Also folded NON-BLOCKING: `spec.proxy` nesting; known-limitations 139–140 split; docs/10 one sentence; confirm `vi.spyOn`; admission POST every field; orig-dest address from state; `spa_test` after embed.

## Skeptic-plan-review sweep 3 (fresh)

**Verdict: BLOCKED** (3 BLOCKING; cap 3 — do not implement). Folds recorded but **not** re-reviewed:

1. App `/status` must stub `sampleState()` with every subtree Status forms read; forms no-op until those subtrees exist. Ports-only stub is Flows-only.
2. 409 `/v1/state` stays `sha256:abc` until after the 409 apply; then `newer` (tie to features refetch, not `stateGets`). Mount + pre-POST OCC remain `abc`.
3. Extract `InterceptChip` as a **child** of `LiveSpecProvider`. `Shell` must not call `useLiveSpec()`.

Also recorded NON-BLOCKING: TacLab vs local ADR 0018; docs/06 `replaceCompat` nest; known-limitations lines 31 and 139; drop REST/MCP help assertion; empty orig-dest address copy; `sampleStatus().features` complete; `featureGets` incrementor; `metrics.listen` muted line; commit `internal/web/dist`.

**Plan review ended BLOCKED.** Implementation is forbidden until a later sweep returns NO BLOCKING FINDINGS.

## Out of repo

Do not touch other repositories. Pin stays v1.5.0 in overlay comments (this repo does not bump mcp-integration-lab).

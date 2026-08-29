# Plan: LabMITM Flows split-pane inspector (operator SPA)

Status: ACCEPT (sweep 3 leftovers folded; no remaining substance blockers)
Owners: Operator UI
Last reviewed: 2026-08-29
Approved mock: Matt-approved Mira Flows redesign (`after.png`)
Scope: **OPERATOR SPA ONLY** (`web/`). Do not change Status/Audit/Reset page internals. Do not add fuzzer/repeater. Do not render captured HTML. Do not expand to other repos. Do not merge.

This document is an implementation contract. Origin `agent-skills` clone was unavailable (CLI `Not logged in`); templates still run.

## Verdict (planning)

Investigate-first. Implement only after review-plan + skeptic-plan-review report **NO BLOCKING FINDINGS**.

## Problem

Today the operator SPA is a light-theme two-route inspector:

- `FlowsPage` (`web/src/pages/FlowsPage.tsx`) lists flows and **navigates away** via `<Link to={/flows/:id}>` (line 100).
- `FlowPage` (`web/src/pages/FlowPage.tsx`) is a full-page detail. Navigating unmounts `FlowsPage`, which **tears down** `useFlowsLive` (`web/src/hooks/useFlowsLive.ts`) and its `EventSource("/v1/events/stream")`.
- CONNECT metadata flows (`internal/proxy/connect.go` `connectFlow`, lines 110–131) store `Method=CONNECT`, `Protocol=connect`, `Intercepted=false`, empty URL/request/response, no TLS. The current detail page shows empty HTTP tables (“No headers.” / “Empty body.”) instead of a tunnel-not-decrypt summary.
- List rows do not show `timings.totalMs`, size, method color, or a first-class tunnel chip (`FlowsPage.tsx` 98–116).
- Chrome is a horizontal navy topbar (`web/src/App.tsx` `Shell`, `web/src/styles.css` `:root` light tokens). The approved mock is dark split-pane: sidebar nav, header chips, IBM Plex.

## Non-goals

- Status / Audit / Reset **page logic** (`StatusPage.tsx` feature catalog + `setFeature`, `AuditPage.tsx`, `ResetPage.tsx` RESET phrase). Those files stay as-is except inheriting global CSS variables.
- New REST/MCP capabilities, catalog rows, apply verbs, or Go domain types.
- Live `GET /v1/state` parsing of `spec.tls.ports` (no SPA client today; `Status.intercept` is boolean-only in `web/src/api/types.ts` 184–192 and `internal/control/rest/dto.go` `statusResponse`).
- Fuzzer, repeater, exploit, SSL-strip, Relay, payload generator (`web/src/ui/forbidden.ts`).
- Optional HTML preview iframe (stays default **off**; never `innerHTML` / `dangerouslySetInnerHTML`).
- Changing bearer session, CSRF (`X-LabMITM-CSRF`), skip-link, or writing tokens to web storage.
- New npm runtime dependencies. No Google Fonts CDN.
- ADR (chrome/UX only; no invariant change).

## Evidence (verified)

| Claim | Evidence |
|---|---|
| List omits bodies **and headers** | `internal/control/rest/dto.go` `fromMessage` 524–537: `listItem` returns `{Size, Truncated}` only |
| List omits WS frames / gRPC messages | same file `fromWebSocket` / `fromGRPC` when `listItem` |
| Inspector needs GET-by-id | `FlowPage.tsx` 246 `getFlow(id)`; docs/08-rest-api.md list vs GET-by-id |
| Raw CONNECT is not intercepted | `connect.go` 119–131 `Intercepted: false`, `Protocol: connect`, no URL |
| Intercept ports default `[443]` | overlay `examples/labmitm.yaml` 69–72; `connect.go` `shouldIntercept` + `portListed` 133–167 (empty ports → 443) |
| LabLDAP LDAPS | `docs/01-architecture.md` 47 `:3636`; overlay comment `directory` LDAPS `:3636` |
| SSE hook | `useFlowsLive.ts` 42 `new EventSource("/v1/events/stream")`; enabled flag + `[enabled, onChange]` deps |
| SPA fallback for `/flows/:id` | `internal/control/rest/spa_test.go` 25–29 — **keep the route** |
| Bundle budget is JS-only | `web/scripts/check-bundle.mjs` 6–9 counts `.js` under `dist/assets` (450 KiB) |
| Nav labels already match mock | `forbidden.ts` `navItems` → Flows / Status / Audit / Reset (Audit/Reset scoped) |
| Auth must not change | `AuthProvider.tsx`, `storage.ts` `assertNoTokenStorage`, `security.test.ts` |
| FlowPage extra surfaces | Trailers / Frames / gRPC **tabs** when data exists; PUSH is `FlowCaptureMeta` text, not a tab (`FlowPage.tsx` 35–41) |

## Design

### 1. Routing so SSE stays mounted

Sibling `<Route path="/" element={<FlowsPage/>}/>` + `<Route path="/flows/:id" element={<FlowPage/>}/>` remounts on navigate. **Single required recipe** — pathless layout parent (not `path="/"` with nested `flows/:id`, and not two recipes):

```tsx
<Route element={<RequireSession />}>
  <Route element={<FlowsWorkspace />}>
    <Route path="/" element={<></>} />
    <Route path="/flows/:id" element={<></>} />
  </Route>
  <Route path="/status" element={<StatusPage />} />
  <Route path="/audit" element={<AuditPage />} />
  <Route path="/reset" element={<ResetPage />} />
</Route>
```

`FlowsWorkspace` reads the id with `useMatch("/flows/:id")`. Render list + inspector in the layout; do not depend on `<Outlet />`.

**Do not mount `<FlowPage />` as the pane.** Extract:

```ts
FlowInspector({ id, embedded, onDeleted }: { id: string; embedded?: boolean; onDeleted?: () => void })
```

- Workspace: `<FlowInspector id={id} embedded />` **only** when `id` is non-empty. `embedded`: no `<main className="page">`, no “Flows” / “Back to flows” link (those landmarks stay on the workspace `<main>`).
- On `/`: empty inspector placeholder; **no** `getFlow("")`.
- `FlowPage` (standalone / existing tests): `const { id = "" } = useParams(); return id ? <FlowInspector id={id} /> : null;` — **omit** `embedded` so tests keep a single `<main className="page">`.
- On `id` change: `setTab("request")`, `setFlow(null)`, clear error, then fetch.
- Keep `FlowCaptureMeta` (stream id, SOCKS dest, original dest, PUSH parent/promised) on HTTP/h2 inspectors.

**App.tsx:** only replace the two flow **sibling** routes under the existing `RequireSession`. Keep `Shell`, `/login`, and `path="*"`. Do not paste the recipe as a full `App` replacement.

`FlowsWorkspace` owns:

- `listAllFlows` + `useFlowsLive(refresh, true)` — **always enabled while this layout is mounted**
- captured list (middle pane)
- selected id from `useMatch("/flows/:id")?.params.id`
- `FlowInspector` when id is set (`getFlow(id)` inside the inspector)

Selecting a row is `<Link to={/flows/${id}}>` (deep-link + SPA fallback stay valid). Do **not** put `EventSource` on `Shell`.

**Delete / SSE (sweep-1 blocker):** `useFlowsLive` today listens only for `flow.inserted`, `flow.paused`, `store.wiped` (`useFlowsLive.ts` 43–45). Store/SSE already emit `flow.deleted` (`internal/app/types.go` 130; `sseType` default returns `t` in `events.go` 66–74). Add `es.addEventListener("flow.deleted", refresh)` and a hook test. Workspace delete calls `deleteFlow` then `navigate("/", { replace: true })`; the new listener (not remount) refreshes the list. Update `docs/08-rest-api.md` SSE event list to include `flow.deleted`.

### 2. List chrome (match mock)

Each row (from **list** JSON — no extra GET per row):

- Method: `GET`/`POST`/… in accent `#6ea8d1`; CONNECT shown as `CONN` in tunnel `#c4a35a` (`methodClass`).
- Authority line: prefer `socks.dest`, else `originalDest`, else `host`. **Do not parse port from `flow.host`.** HTTP CONNECT stores hostname only (`connect.go` `splitAuthority` + `connectFlow` `Host: host`; SOCKS `socksFlow` same — port lives on `SOCKS.Dest` only).
- Path / subtitle: HTTP path from `url`; successful CONNECT tunnel → `CONNECT · LDAPS` only when `socks.dest` / `originalDest` ends with `:3636` or `:636`, or hostname is `directory` (overlay comment). Otherwise `CONNECT · tunnel`.
- Right: `timings.totalMs` as `12ms`, or `-` when `totalMs === 0` **and** tunnel-not-decrypt; status is `tunnel` (gold) only when `isTunnelNotDecrypt`; else keep `status > 0 ? status : state` (SOCKS CONNECT and `connectErrFlow` often have `Status: 0`). List size: `formatBytes(requestBytes)` / `formatBytes(responseBytes)` when non-zero (mock in/out).
- Size: optional compact `formatBytes(requestBytes+responseBytes)` if it fits the mock density; inspector header already shows in/out.
- Selected row uses panel/elevated highlight (`#181a1f` / slightly lighter).
- Single search input placeholder **Host, method, or status**. Client-side filter on already-loaded items (`host`, `url`, `method`, `status`, `state`). Do not drop `listAllFlows` pagination walk.
- Keep write-scoped **Clear flows** (existing `clearFlows` + confirm). Not in the mock; keep as a secondary control near the search so we do not remove a shipped capability.
- Keep no-fuzzer assertion.

Tunnel-not-decrypt helper (pure, unit-tested in `web/src/ui/flowKind.ts`). **`socksFlow` always sets `Method: CONNECT`** (`socks.go` 540–556), including BIND (`Command=bind`) and UDP ASSOCIATE (`Command=udp`). **Do not** use a bare `method === "CONNECT"` clause.

```
isTunnelNotDecrypt(flow):
  !flow.intercepted
  && !flow.error
  && (flow.state === "completed" || flow.status === 200)
  && (
       flow.protocol === "connect"
       || (
            (flow.protocol === "socks5" || flow.protocol === "socks4")
            && (flow.socks?.command ?? "connect") === "connect"
          )
     )
```

**Do not** classify intercept-attempt failures as tunnels (`connectErrFlow` `tls_handshake|upstream_tls|http2_inner`; DNS/403 with `Error` set). **Do not** classify SOCKS BIND/UDP completed rows as tunnels (unit-test `socks.command: bind|udp` → false). **Do not** classify intercepted inner GET/POST as tunnels.

LDAPS subtitle **only** when `socks.dest` or `originalDest` ends with `:3636` or `:636`. HTTP CONNECT to hostname `directory` is `CONNECT · tunnel` (no port on `host`; `:3389`/`:8443` are not LDAPS). Footer copy covers LDAPS/TacLab. Do not invent a TacLab TLS port table.

Search matches `protocol`, aliases `CONN`/`CONNECT`, and `tunnel`. `refresh` must be `useCallback(..., [])` only (read filter from a ref if needed). **Do not** put `storeGeneration` or the search string in `onChange` deps — that reconnects EventSource (`useFlowsLive` `[enabled, onChange]`). Filter `items` in render. Keep generation in state for display only.

### 3. Inspector (selection drives Request / Response / TLS)

On select, `getFlow(id)` (list has no headers/bodies — `dto.go` 524–537).

**HTTP / intercepted flows** (`intercepted: true` or non-CONNECT HTTP):

- Title: `{method} {url}` (existing heading contract).
- Summary: `{status} · {totalMs}ms · {formatBytes(requestBytes)} in · {formatBytes(responseBytes)} out`.
- Chips: **intercepted** (accent) when `flow.intercepted`; **tunnel-not-decrypt** (gold) when helper is true; protocol chip (`HTTP/1.1` / `h2` / …).
- Tabs: Request, Response, TLS always. **Keep** Trailers / Frames / gRPC when those fields exist (1.1/1.2 contract + `FlowPage.test.tsx`). Do not add fuzzer/repeater.
- Request pane: bordered raw box matching the mock (`GET /v1/status HTTP/1.1` + headers). Implement as escaped `<pre className="raw">` built from method/path/protocol + `headers[]` (React text, never `innerHTML`). Keep download attachment + `preventDefault` + `downloadFlowBody`.
- Response / TLS / Frames / gRPC / trailers: keep current escaped-text / hex / dl behavior.

**CONNECT tunnel flows** (`isTunnelNotDecrypt`):

- Do **not** show empty “No headers / Empty body” on **Request or Response** (same summary on both). Hide empty-body download links on those rows.
- Tunnel summary: authority (see list rule) + static **why not decrypted: port not in tls.ports:[443]**. **Do not interpolate port N.**
- TLS tab: existing “No TLS metadata…” is correct for raw CONNECT.
- Delete: write-scoped; workspace `onDeleted` calls the same `refresh()` as Clear (`FlowsPage.tsx` 41–42) **and** `navigate("/", { replace: true })`. `flow.deleted` on `useFlowsLive` is the live path; do not rely on remount.

### 4. Dark chrome (App shell + CSS only)

`web/src/styles.css` tokens (match mock):

| Token | Value |
|---|---|
| bg | `#0b0c0e` |
| elev | `#121317` |
| panel | `#181a1f` |
| fg | `#ecece8` |
| accent | `#6ea8d1` |
| tunnel | `#c4a35a` |

`color-scheme: dark`. Also remap `--card` → elev/panel, `--muted`, `--line`, `--accent-fg`, `--err-*`, `--warn-bg` so Status/Audit/Reset tables remain readable. **Do not** use `--accent` as the header/topbar fill (today `.topbar { background: var(--accent) }` would become light blue). New shell classes: sidebar + header on `#0b0c0e` / `#121317`. Replace hardcoded `.flow-list a:hover { background: #e7edf2 }`. Font stack: `"IBM Plex Sans", "IBM Plex Mono", ui-sans-serif, sans-serif`; mono for `pre.raw`.

**IBM Plex:** vendor three OFL-1.1 woff2 **in this PR** (no CI fetch): `IBMPlexSans-Regular.woff2`, `IBMPlexSans-Medium.woff2`, `IBMPlexMono-Regular.woff2` under `web/src/fonts/` (import from `styles.css`). Put `OFL.txt` in `web/public/` so Vite copies it into `dist` and `web-embed` ships it. Pin `github.com/IBM/plex` in the PR body. Mention OFL in CHANGELOG. **No** Google CDN, **no** npm font package. Faux-bold on `.brand` is acceptable.

`App.tsx` `Shell` (signed-in):

- Header: brand **LabMITM** + small accent status dot; chips **live** (accent) and **:443 intercept only** (muted); **Sign out** outline button.
- Flows nav stays active on `/flows/:id` (`NavLink` today uses `end={to === "/"}` in `App.tsx` 23 — treat `/` and `/flows/*` as Flows).
- **live** chip is chrome copy (mock), **not** a second EventSource. Flows workspace still uses `useFlowsLive`.
- **:443 intercept only** is chrome copy of the overlay/default intercept set (`examples/labmitm.yaml` `ports: [443]`), not a live `replaceTLS` readout (`GET /v1/status` has no ports).
- Left nav: existing `navItems(canAudit, canReset)` — Flows / Status / Audit / Reset. Do **not** un-gate Audit/Reset.
- Skip-link `#app-main` stays.
- Login page: inherit dark tokens; do not redesign the bearer form.

Flows workspace footer (mock):

> CONNECT to LDAPS/TacLab TLS is tunnel-not-decrypt. Intercept is :443 only.

### 5. Auth / XSS invariants (must not regress)

- Cookie session + memory CSRF only (`client.ts`, `AuthProvider.tsx`).
- `assertNoTokenStorage` on `apiFetch`.
- `security.test.ts` walk: no `dangerouslySetInnerHTML`, no `.innerHTML =`, no token keys in storage, no forbidden control labels.
- Body downloads stay attachment + blob (`security.test.ts` 45–51).
- `shouldRenderAsText` / `toHexDump` unchanged.

### 6. Tests (fail before / pass after)

| File | What |
|---|---|
| `web/src/ui/flowKind.ts` + `.test.ts` (new) | `isTunnelNotDecrypt` true only for successful raw CONNECT / SOCKS CONNECT; false for `tls_handshake` / `http2_inner` / DNS / BIND / UDP. LDAPS subtitle **only** from `socks.dest` or `originalDest` ending `:3636`/`:636`. False for HTTP CONNECT `host: "directory"` and for `host` ending `:3636` (host is not a port field) |
| `useFlowsLive.test.ts` | Listener set includes `flow.deleted` |
| `FlowsWorkspace.test.tsx` (new; not `renderApp(<FlowsPage/>)` alone) | Mount `FlowsWorkspace` (or exported `AppRoutes` **without** `BrowserRouter`) under `renderApp` so `/` and `/flows/:id` share one layout. Stub list vs GET-by-id **and** stub `EventSource` (global `web/src/test/setup.ts` 44–54 is a no-op and does **not** record instances — tests that count ES must `vi.stubGlobal` their own fake). New list chrome. Select h2 row → stream / SOCKS dest / original dest in inspector. CONNECT completed → `CONN` + `tunnel`. Search `CONN`/`tunnel`. One EventSource across select. **No** fuzzer/repeater |
| `FlowPage.test.tsx` | Keep escaped HTML, Frames, gRPC, trailers, SOCKS dest, original dest, PUSH ids, download attachment. Add CONNECT completed fixture: static tunnel summary; Request tab is **not** empty-headers primary. Add `tls_handshake` CONNECT: error, not tunnel summary |
| `App` chrome test | Do **not** nest `<App />` (has `BrowserRouter`) inside `renderApp` (`MemoryRouter`). Export `Shell` or `AppRoutes` without the router. Assert skip-link, LabMITM, live + `:443 intercept only`, Sign out, nav labels. Navigate to `/flows/:id` and assert Flows stays `nav-active` |
| `StatusPage.test.tsx` / `ResetPage.test.tsx` / `LoginPage.test.tsx` | Re-run unchanged (internals untouched) |
| `security.test.ts` | Update file path if download helpers move; keep XSS/storage/forbidden scans |

Do **not** delete or weaken existing assertions unless the old list accessible-name is provably obsolete; then **replace** with equivalent coverage on the new chrome (method/status/tunnel/totalMs + inspector metadata).

### 7. Docs (same change)

Update **Last reviewed** on touched numbered docs:

- `docs/01-architecture.md` Embedded operator UI **Pages** + **Live update**: split-pane; SSE stays mounted; chips; CONNECT tunnel summary. State that the `:443 intercept only` chip and footer are **overlay/default chrome copy**, not live `GET /v1/state` `tls.ports`.
- `docs/03-tls-interception.md` one sentence: operator SPA shows raw CONNECT as tunnel-not-decrypt (port not in default `tls.ports:[443]`); handshake failure is still D20 (error, not that chip).
- `docs/08-rest-api.md` Embedded operator UI table **and** SSE event list (`flow.deleted`).
- `docs/12-testing-strategy.md` UI row: split-pane, tunnel chip, EventSource stays mounted, `flow.deleted` refresh.
- `web/README.md` Pages / Live update (today: “flow list, flow detail”).
- `docs/known-limitations.md` residual: chip/footer/reason are default overlay copy; live `replaceTLS` ports are not shown.
- `CHANGELOG.md` Unreleased **Changed**: operator Flows inspector split-pane / dark chrome / tunnel-not-decrypt (SPA only).
- `README.md` only if a sentence still says “list then a separate detail page”.

Cross-links stay absolute HTTPS `https://github.com/hilather/go-lab-mitmproxy/blob/main/...`.

### 8. Embed / CI

1. `make web-test` (Vitest).
2. `make web-build` (tsc + Vite + `check-bundle.mjs` + copy `web/dist` → `internal/web/dist` for `go:embed`).
3. `make test-docs` + `make test-changelog` after doc/changelog edits.
4. No `make generate` (no OpenAPI/schema change).
5. `internal/control/rest/spa_test.go` must still see `LabMITM` in `GET /` and `GET /flows/01JTEST`.

### 9. Implementation order

1. `flowKind` helper + unit tests (port-suffix LDAPS only; BIND/UDP/handshake false).
2. CSS tokens + `@font-face` + `App.tsx` shell (sidebar, chips, skip-link).
3. Pathless `FlowsWorkspace` layout (full-bleed class, **not** `.page`) + list + `FlowInspector` extract (`embedded` in the pane). Status/Audit/Reset keep `.page`.
4. Tunnel summary + chips + raw request `<pre>`.
5. Update / add Vitest; keep security scan.
6. Docs + CHANGELOG.
7. `make web-test` then `make web-build`.
8. Commit, push, draft PR. Do not merge. Hold for Matt.

### 10. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Child route elements | Empty fragment; layout does not use `<Outlet />` for the inspector |
| Pathless layout remounts anyway | Test EventSource instance count across `user.click` of a flow link |
| CONNECT host has no port | Static reason sentence; authority from `socks.dest` / `originalDest` / `host` |
| List used for inspector bodies | Forbidden — always `getFlow` |
| Dark CSS breaks Status tables | Reuse existing class names (`.page`, `.data`, `.badge`); only tokens change; Status tests still query roles/text |
| Font fetch fails in CI sandbox | Vendor woff2 + OFL in-tree in this PR |
| Bundle / embed drift | `web-build` in the same commit as `web/src` |

## Out of repo

Do not touch other repositories. Origin skills clone/auth failed; planning still used the skeptic template on this tree.

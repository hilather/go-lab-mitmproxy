# ADR 0011: Optional compat flow REST

Status: Accepted
Date: 2026-08-19
Decisions: D23, D24, D33, D39, D40, D43, D52

## Context

ADR 0007 **D5** made native management `/v1` + `POST /mcp` only: no mitmproxy REST, mitmweb, or Python addon protocol in 1.0. Operators scripted against mitmweb `/flows` still have no bounded shim. There is still no `mcp-integration-lab` mitmproxy API consumer (D18).

This ADR supersedes ADR 0007 D5’s **“no compat path in 1.0” sentence** only. **D5 native `/v1` + MCP primacy stands.** There is still no Python mitmproxy wrap/exec, no mitmweb SPA, no dumpfile, no addon VM, and no HTTP Basic. **D7 stands.**

## Decision

**D23 — No Python mitmproxy.** First-party Go adapter over `internal/app`.

**D24 — Compat surface is thin flow REST only.** Default prefix `/compat`. Subset: list/get/delete/clear/replay + raw content. Out: mitmweb, dumpfile, CLI flags, addon, Basic, PUT mutate.

**D33 — Extra `/compat` paths are not on `catalog()` rows that `compileRoutes` walks** until the compat workstream. Foundation keeps them in `capabilities.CompatBindings()` (a side table). `TableRowCount` stays 30. Disposition: `REST_ONLY_PROTOCOL` extra spellings of existing `flows.*` IDs. No new MCP tools.

**D39 — No mitmproxy CLI flags.** YAML only.

**D40 — D5 native `/v1` + MCP primacy stands.** Compat is optional, default-off, must not collide with configured `restPath` / `mcpPath`. Catalog id remains `labmitm`.

**D43 — Validate `compat.flowREST.pathPrefix` against configured `listeners.management.restPath` and `mcpPath`**, not literals. Cookie mutations still require CSRF. `Authorization: Basic` stays 401 Bearer.

**D52 — Compat list is at most 200 newest flows**, JSON array body, `X-LabMITM-Truncated: true` when more exist. Native `/v1/flows` remains the paginated API.

`spec.compat.flowREST.enabled` defaults false and is Reset-only (D51). `spec.compat.mitmproxyREST` stays reserved.

## Consequences

- Native catalog REST paths stay `/v1` only. `compileRoutes` must not see `/compat` in the foundation PR.
- Enable/disable requires bootstrap YAML + Reset.
- D7 is **not** superseded.

## Alternatives considered

- Extra `/compat` bindings on `catalog()` in the foundation PR: rejected (D33). Would serve native JSON.
- `dispatchMount` for compat: rejected. Pre-auth, skips CSRF.
- mitmweb / dumpfile / CLI-flag clone: rejected (D24, D39).
- Wrap/exec Python mitmproxy: rejected (D23).

## Review triggers

Review when a named consumer appears, when OpenAPI should emit CompatBindings paths, or when a second compat surface (dumpfile, mitmweb) is proposed (it needs a new ADR).

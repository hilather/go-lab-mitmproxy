# Control Plane and REST/MCP Parity

Status: Proposed normative behavior
Owners: Application, REST, MCP
Last reviewed: 2026-08-18 (FND-001)
Related ADRs: 0004, 0005, 0006, 0007

REST and MCP are two protocol adapters over one capability model. Adapters never call each other and never contain proxy/store business logic. See [docs/adr/0004-shared-capability-registry.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0004-shared-capability-registry.md).

## Package layout

```
internal/capabilities     declarations (no app import)
internal/app              Service methods
internal/control/rest     HTTP /v1
internal/control/mcp      Streamable HTTP /mcp
internal/auth             bearer → Principal
internal/audit            ring
```

There is **no** `internal/control/compat`.

## Dispositions

| Disposition | Examples |
|---|---|
| `PARITY_REQUIRED` | flows list/get/delete/clear/wait/resume/drop/replay, state get/validate/export/reset, status, schema, audit, changes plan/apply, ca get |
| `REST_ONLY_PROTOCOL` | live/ready, OpenAPI, UI assets, session/CSRF, `/v1/metrics`, raw body download `Content-Type` streams |
| `MCP_ONLY_PROTOCOL` | `tools/list`, `resources/list`, protocol negotiate |
| `PARITY_DIFFERENT_BINDING` | `events.stream`: REST SSE vs MCP `subscriptions/listen` URI-only notify + `mitm_flows_list` |
| `EXEMPT_BY_ADR` | no OAuth PRM (ADR 0005) |

## Scopes and roles

```
mitm.read          list/get/wait/status/schema/state get/ca get
mitm.write         delete, clear, resume, drop, replay
mitm.admin         reset, plan/apply, export
mitm.audit.read    audit ring
```

`mitm.admin` satisfies all scopes. `mitm.write` does **not** include reset.

| Role | Scopes |
|---|---|
| viewer | `mitm.read` |
| operator | `mitm.read`, `mitm.write` |
| administrator | all |

## Capability table (frozen names)

| Capability ID | REST | MCP tool / resource | Scopes | Notes |
|---|---|---|---|---|
| `health.live` | `GET /v1/health/live` | — | none | REST_ONLY |
| `health.ready` | `GET /v1/health/ready` | — | none | REST_ONLY |
| `version.get` | `GET /v1/version` | `mitm_version_get` | `mitm.read` | |
| `capabilities.get` | `GET /v1/capabilities` | `mitm_capabilities_get`, `labmitm://capabilities` | `mitm.read` | |
| `status.get` | `GET /v1/status` | `mitm_status_get`, `labmitm://status` | `mitm.read` | listeners, store stats, revisions, intercept on/off, `ca.{mode,spkiSha256,subject,notAfter}` (never key) |
| `schema.get` | `GET /v1/schema/config` | `mitm_schema_get`, `labmitm://schema/config` | `mitm.read` | |
| `state.get` | `GET /v1/state` | `mitm_state_get`, `labmitm://state` | `mitm.read` | redacted spec + revisions |
| `state.validate` | `POST /v1/state:validate` | `mitm_state_validate` | `mitm.admin` | |
| `state.export` | `GET /v1/state:export` | `mitm_state_export` | `mitm.admin` | |
| `state.reset` | `POST /v1/state:reset` | `mitm_state_reset` | `mitm.admin` | wipe flows; new generate-mode CA |
| `changes.plan` | `POST /v1/changes:plan` | `mitm_change_plan` | `mitm.admin` | |
| `changes.apply` | `POST /v1/changes:apply` | `mitm_change_apply` | `mitm.admin` | `expectedRevision` required |
| `session.create` | `POST /v1/session` | — | none (bearer) | REST_ONLY; cookie + CSRF |
| `session.delete` | `DELETE /v1/session` | — | cookie | REST_ONLY |
| `session.get` | `GET /v1/session` | — | cookie or bearer | REST_ONLY |
| `events.stream` | `GET /v1/events/stream` | `subscriptions/listen` on `labmitm://flows` | `mitm.read` | PARITY_DIFFERENT_BINDING |
| `flows.list` | `GET /v1/flows` | `mitm_flows_list`, `labmitm://flows` | `mitm.read` | cursor pagination |
| `flows.get` | `GET /v1/flows/{id}` | `mitm_flow_get`, `labmitm://flows/{id}` | `mitm.read` | headers + truncated bodies |
| `flows.request` | `GET /v1/flows/{id}/request` | `mitm_flow_request_get` | `mitm.read` | raw request body |
| `flows.response` | `GET /v1/flows/{id}/response` | `mitm_flow_response_get` | `mitm.read` | raw response body |
| `flows.delete` | `DELETE /v1/flows/{id}` | `mitm_flow_delete` | `mitm.write` | |
| `flows.clear` | `DELETE /v1/flows` | `mitm_flows_clear` | `mitm.write` | |
| `flows.wait` | `POST /v1/flows:wait` | `mitm_flows_wait` | `mitm.read` | filter + timeout |
| `flows.resume` | `POST /v1/flows/{id}:resume` | `mitm_flow_resume` | `mitm.write` | breakpoint |
| `flows.drop` | `POST /v1/flows/{id}:drop` | `mitm_flow_drop` | `mitm.write` | breakpoint |
| `flows.replay` | `POST /v1/flows/{id}:replay` | `mitm_flow_replay` | `mitm.write` | new flow id |
| `ca.get` | `GET /v1/ca` | `mitm_ca_get`, `labmitm://ca` | `mitm.read` | PEM cert only, never key |
| `audit.list` | `GET /v1/audit` | `mitm_audit_query`, `labmitm://audit/recent` | `mitm.audit.read` | |
| `audit.get` | `GET /v1/audit/{eventId}` | `mitm_audit_get` | `mitm.audit.read` | |
| `metrics.get` | `GET /v1/metrics` | — | `mitm.read` | REST_ONLY; only if `publicPath: true` |

`make generate` writes `api/capabilities/v1.json`, `api/openapi/v1.json`, `api/mcp/v1.json`, `api/metrics/v1alpha1.json`. CI `verify-generated` fails on drift.

Renaming a tool, resource, or REST path requires an ADR plus catalog + design-table change. MCP tool names `mitm_*` are frozen.

## Parity rules

- Every public REST write operation has one or more MCP tools with equivalent semantics, except `REST_ONLY_PROTOCOL`.
- Every MCP mutation tool has a REST operation.
- REST GET representations may map to MCP resources or read tools.
- Status codes and JSON-RPC codes differ by transport, but domain error codes and error data match.
- Pagination, filtering, revisions, and authorization semantics match.
- Default values are applied in the shared application layer.
- Audit records identify the original transport but otherwise use the same event schema.
- Proxy insert stays on the data plane, not the capability registry.

## Related documents

- REST shapes: [docs/08-rest-api.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/08-rest-api.md)
- MCP pin: [docs/09-mcp-api.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/09-mcp-api.md)

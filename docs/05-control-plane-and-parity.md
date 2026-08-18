# Control Plane and REST/MCP Parity

Status: Proposed normative behavior
Owners: Application, REST, MCP
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0004, 0005, 0006, 0008

REST and MCP are two protocol adapters over one capability model. Adapters never call each other and never contain proxy/store business logic. See [docs/adr/0004-shared-capability-registry.md](adr/0004-shared-capability-registry.md).

The mitmweb compat adapter also calls `app.Service`. It is `REST_ONLY_PROTOCOL`. Every compat control still has a native `/v1` + MCP twin.

## Package layout

```
internal/capabilities     declarations (no app import)
internal/app              Service methods
internal/control/rest     HTTP /v1
internal/control/mcp      Streamable HTTP /mcp
internal/control/compat   mitmweb shim → app.Service
internal/auth             bearer + basic → Principal
internal/audit            ring
```

## Dispositions

| Disposition | Examples |
|---|---|
| `PARITY_REQUIRED` | flows CRUD/wait/dump/har/replay/resume/kill, state, intercept, transforms via plan/apply, scripts, audit, status |
| `REST_ONLY_PROTOCOL` | live/ready, OpenAPI, UI assets, session/CSRF, `/v1/metrics`, mitmweb routes, SPA, content **preview document** if CSP iframe is used, `GET /v1/ca/cert.p12` file download |
| `MCP_ONLY_PROTOCOL` | `tools/list`, `resources/list`, protocol negotiate |
| `PARITY_DIFFERENT_BINDING` | `events.stream`: REST SSE vs MCP `subscriptions/listen` URI-only notify + `mitm_flows_list`. Compat WebSocket `/updates` vs SSE. |
| `EXEMPT_BY_ADR` | no OAuth PRM (ADR 0005); no `options.save` to disk (ADR 0003) |

## Scopes

```
mitm.read          list/get/wait/dump/har/status/schema/state get/ca cert (public)
mitm.write         update/delete/clear/resume/kill/replay/mark/comment/content
mitm.admin         reset, plan/apply config, export, tls verify, store caps
mitm.audit.read    audit ring
mitm.script        load/unload Starlark
```

`mitm.admin` satisfies all scopes except `mitm.script` unless listed. Administrator role includes `mitm.script`. `mitm.write` does **not** include reset or CA key export.

| Role | Scopes |
|---|---|
| viewer | `mitm.read` |
| operator | `mitm.read`, `mitm.write` |
| administrator | all |

CA **private key** export is `mitm.admin` and disabled unless `spec.tls.allowKeyExport: true` (default **false**; field must exist as default-false). MCP tool `mitm_ca_key_export` returns `forbidden` when disabled.

## Capability table (frozen names)

Renaming a tool, resource, or REST path requires an ADR plus catalog + manifest + this table.

### Meta, health, state

| Capability ID | REST | MCP tool / resource | Scopes | Notes |
|---|---|---|---|---|
| `health.live` | `GET /v1/health/live` | — | none | REST_ONLY |
| `health.ready` | `GET /v1/health/ready` | — | none | REST_ONLY |
| `version.get` | `GET /v1/version` | `mitm_version_get` | `mitm.read` | |
| `capabilities.get` | `GET /v1/capabilities` | `mitm_capabilities_get`, `labmitm://capabilities` | `mitm.read` | |
| `status.get` | `GET /v1/status` | `mitm_status_get`, `labmitm://status` | `mitm.read` | listeners, store stats, revisions, intercept |
| `schema.get` | `GET /v1/schema/config` | `mitm_schema_get`, `labmitm://schema/config` | `mitm.read` | |
| `state.get` | `GET /v1/state` | `mitm_state_get`, `labmitm://state` | `mitm.read` | redacted spec + revisions |
| `state.validate` | `POST /v1/state:validate` | `mitm_state_validate` | `mitm.admin` | |
| `state.export` | `GET /v1/state:export` | `mitm_state_export` | `mitm.admin` | |
| `state.reset` | `POST /v1/state:reset` | `mitm_state_reset` | `mitm.admin` | wipe flows |
| `changes.plan` | `POST /v1/changes:plan` | `mitm_change_plan` | `mitm.admin` | |
| `changes.apply` | `POST /v1/changes:apply` | `mitm_change_apply` | `mitm.admin` | expectedRevision required |
| `session.create` | `POST /v1/session` | — | none | REST_ONLY |
| `session.delete` | `DELETE /v1/session` | — | cookie | REST_ONLY |
| `session.get` | `GET /v1/session` | — | cookie or bearer | REST_ONLY |
| `metrics.get` | `GET /v1/metrics` | — | `mitm.read` | REST_ONLY; only if `publicPath` |

### Flows

| Capability ID | REST | MCP tool / resource | Scopes | Notes |
|---|---|---|---|---|
| `flows.list` | `GET /v1/flows` | `mitm_flows_list`, `labmitm://flows` | `mitm.read` | filter, cursor |
| `flows.get` | `GET /v1/flows/{id}` | `mitm_flow_get`, `labmitm://flows/{id}` | `mitm.read` | |
| `flows.update` | `PUT /v1/flows/{id}` | `mitm_flow_update` | `mitm.write` | headers/path/method/status/comment/mark |
| `flows.delete` | `DELETE /v1/flows/{id}` | `mitm_flow_delete` | `mitm.write` | |
| `flows.clear` | `DELETE /v1/flows` | `mitm_flows_clear` | `mitm.write` | |
| `flows.duplicate` | `POST /v1/flows/{id}:duplicate` | `mitm_flow_duplicate` | `mitm.write` | |
| `flows.resume` | `POST /v1/flows/{id}:resume` | `mitm_flow_resume` | `mitm.write` | |
| `flows.resume_all` | `POST /v1/flows:resume` | `mitm_flows_resume` | `mitm.write` | optional filter |
| `flows.kill` | `POST /v1/flows/{id}:kill` | `mitm_flow_kill` | `mitm.write` | |
| `flows.kill_all` | `POST /v1/flows:kill` | `mitm_flows_kill` | `mitm.write` | |
| `flows.replay_client` | `POST /v1/flows/{id}:replay` | `mitm_flow_replay_client` | `mitm.write` | |
| `flows.replay_server_load` | `POST /v1/replay/server:load` | `mitm_replay_server_load` | `mitm.write` | body: flow ids or dump |
| `flows.revert` | `POST /v1/flows/{id}:revert` | `mitm_flow_revert` | `mitm.write` | |
| `flows.mark` | `POST /v1/flows/{id}:mark` | `mitm_flow_mark` | `mitm.write` | |
| `flows.wait` | `POST /v1/flows:wait` | `mitm_flows_wait` | `mitm.read` | |
| `flows.dump_export` | `GET /v1/flows:dump` | `mitm_flows_dump_export` | `mitm.read` | JSONL |
| `flows.dump_import` | `POST /v1/flows:dump` | `mitm_flows_dump_import` | `mitm.write` | JSONL or HAR |
| `flows.har_export` | `GET /v1/flows:har` | `mitm_flows_har_export` | `mitm.read` | |
| `flows.content_get` | `GET /v1/flows/{id}/{part}/content` | `mitm_flow_content_get` | `mitm.read` | part=request\|response\|messages |
| `flows.content_set` | `PUT /v1/flows/{id}/{part}/content` | `mitm_flow_content_set` | `mitm.write` | |
| `flows.content_view` | `GET /v1/flows/{id}/{part}/views/{view}` | `mitm_flow_content_view` | `mitm.read` | |

### Intercept, view, commands, scripts, CA, audit, events

| Capability ID | REST | MCP tool / resource | Scopes | Notes |
|---|---|---|---|---|
| `intercept.get` | `GET /v1/intercept` | `mitm_intercept_get` | `mitm.read` | |
| `intercept.set` | `PUT /v1/intercept` | `mitm_intercept_set` | `mitm.write` | also via plan/apply |
| `view.get` | `GET /v1/view` | `mitm_view_get` | `mitm.read` | filter + order |
| `view.set` | `PUT /v1/view` | `mitm_view_set` | `mitm.write` | |
| `filter.help` | `GET /v1/filter-help` | `mitm_filter_help` | `mitm.read` | |
| `commands.list` | `GET /v1/commands` | `mitm_commands_list` | `mitm.read` | frozen catalog |
| `commands.execute` | `POST /v1/commands/{cmd}` | `mitm_command_execute` | by command | only catalogued cmds; maps to app.Service |
| `scripts.list` | `GET /v1/scripts` | `mitm_scripts_list` | `mitm.script` | |
| `scripts.load` | `POST /v1/scripts:load` | `mitm_scripts_load` | `mitm.script` | |
| `scripts.unload` | `POST /v1/scripts:unload` | `mitm_scripts_unload` | `mitm.script` | |
| `ca.cert` | `GET /v1/ca/cert` | `mitm_ca_cert_get` | `mitm.read` | PEM cert only |
| `ca.key_export` | `GET /v1/ca/key` | `mitm_ca_key_export` | `mitm.admin` | default forbidden |
| `audit.list` | `GET /v1/audit` | `mitm_audit_query`, `labmitm://audit/recent` | `mitm.audit.read` | |
| `audit.get` | `GET /v1/audit/{eventId}` | `mitm_audit_get` | `mitm.audit.read` | |
| `events.stream` | `GET /v1/events/stream` | `subscriptions/listen` on `labmitm://flows` | `mitm.read` | PARITY_DIFFERENT_BINDING |
| `events.list` | `GET /v1/events` | `mitm_events_list` | `mitm.read` | log ring |

`make generate` writes `api/capabilities/v1.json`, `api/openapi/v1.json`, `api/mcp/v1.json`. CI `verify-generated` fails on drift.

MCP tool names `mitm_*` are frozen.

## Command catalog (commands.execute)

`commands.execute` is **not** a backdoor around scopes. Each command is a row that already exists as a first-class capability. Unknown commands → `unsupported_capability`.

| Command | Capability | Notes |
|---|---|---|
| `view.clear` | `flows.clear` | |
| `view.resume` | `flows.resume_all` | |
| `view.kill` | `flows.kill_all` | |
| `replay.client` | `flows.replay_client` | arg: flow id |
| `flow.resume` | `flows.resume` | |
| `flow.kill` | `flows.kill` | |
| `flow.duplicate` | `flows.duplicate` | |
| `flow.revert` | `flows.revert` | |
| `flow.set` | `flows.update` | |
| `options.reset` | `state.reset` | lab: reset, not mitmproxy confdir write |
| `export.har` | `flows.har_export` | |
| `export.dump` | `flows.dump_export` | |
| `intercept.toggle` | `intercept.set` | |
| `script.load` | `scripts.load` | |
| `script.unload` | `scripts.unload` | |

Console-only commands (`console.*`) are **not** registered.

## Parity rules

- Every public REST write operation has one or more MCP tools with equivalent semantics, except `REST_ONLY_PROTOCOL`.
- Every MCP mutation tool has a REST operation.
- REST GET representations may map to MCP resources or read tools.
- Status codes and JSON-RPC codes differ by transport, but domain error codes and error data match.
- Pagination, filtering, revisions, and authorization semantics match.
- Default values are applied in the shared application layer.
- Audit records identify the original transport but otherwise use the same event schema.
- Proxy insert stays on the data plane, not the capability registry.
- `make test-parity` walks every `PARITY_REQUIRED` row: same input types, scopes, errors, side effects.

## Related documents

- REST shapes: [docs/06-rest-api.md](06-rest-api.md)
- MCP pin: [docs/07-mcp-api.md](07-mcp-api.md)
- Compat: [docs/12-mitmweb-compat.md](12-mitmweb-compat.md)

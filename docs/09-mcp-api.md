# MCP API

Status: Proposed normative behavior
Owners: MCP, Application
Last reviewed: 2026-08-18 (FND-001)
Related ADRs: 0004, 0006

Native management API is `/v1` + `POST /mcp`. Capability IDs and tool names are frozen in [docs/07-control-plane-and-parity.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/07-control-plane-and-parity.md). Protocol pin: [docs/adr/0006-pin-mcp-protocol-versions.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0006-pin-mcp-protocol-versions.md).

## Transport and pin

- SDK: `github.com/modelcontextprotocol/go-sdk v1.7.0`
- Protocol: `2026-07-28`
- Transport: Streamable HTTP `POST /mcp` on the management listener
- Optional: `labmitm mcp-stdio --config … --token-file …` (stdout = protocol, stderr = logs; `--token-file` required)
- `Stateless: true`
- Auth: bearer only
- Origin check: same as REST (**missing Origin allowed**; D15)
- Pin recorded in `internal/buildinfo` and `/v1/version`
- `spec.management.mcp.allowLegacyClients` default **false** (D15). Integration-lab overlay sets `true`. Cite family docs for the MCPJungle compatibility knob; do not treat `mark3labs/mcp-go v0.48` as a measured image pin.
- `subscriptions/listen` stays 2026-07-28 even when the pin is relaxed.

Tool input/output schemas are generated from the same Go request/response types as REST. MCP structured content is the operation result **without** the HTTP problem envelope; domain `code` is always present on errors.

Resources mirror GET representations. Clients without resource support use the `mitm_*` read tools.

## Tools (frozen)

| Tool | Capability | Scopes |
|---|---|---|
| `mitm_version_get` | `version.get` | `mitm.read` |
| `mitm_capabilities_get` | `capabilities.get` | `mitm.read` |
| `mitm_status_get` | `status.get` | `mitm.read` |
| `mitm_schema_get` | `schema.get` | `mitm.read` |
| `mitm_state_get` | `state.get` | `mitm.read` |
| `mitm_state_validate` | `state.validate` | `mitm.admin` |
| `mitm_state_export` | `state.export` | `mitm.admin` |
| `mitm_state_reset` | `state.reset` | `mitm.admin` |
| `mitm_change_plan` | `changes.plan` | `mitm.admin` |
| `mitm_change_apply` | `changes.apply` | `mitm.admin` |
| `mitm_flows_list` | `flows.list` | `mitm.read` |
| `mitm_flow_get` | `flows.get` | `mitm.read` |
| `mitm_flow_request_get` | `flows.request` | `mitm.read` |
| `mitm_flow_response_get` | `flows.response` | `mitm.read` |
| `mitm_flow_delete` | `flows.delete` | `mitm.write` |
| `mitm_flows_clear` | `flows.clear` | `mitm.write` |
| `mitm_flows_wait` | `flows.wait` | `mitm.read` |
| `mitm_flow_resume` | `flows.resume` | `mitm.write` |
| `mitm_flow_drop` | `flows.drop` | `mitm.write` |
| `mitm_flow_replay` | `flows.replay` | `mitm.write` |
| `mitm_ca_get` | `ca.get` | `mitm.read` |
| `mitm_audit_query` | `audit.list` | `mitm.audit.read` |
| `mitm_audit_get` | `audit.get` | `mitm.audit.read` |

Health live/ready, OpenAPI, UI assets, session/CSRF, and `/v1/metrics` are **not** MCP tools.

## Resources (frozen)

| URI | Capability |
|---|---|
| `labmitm://capabilities` | `capabilities.get` |
| `labmitm://status` | `status.get` |
| `labmitm://schema/config` | `schema.get` |
| `labmitm://state` | `state.get` |
| `labmitm://flows` | `flows.list` |
| `labmitm://flows/{id}` | `flows.get` |
| `labmitm://ca` | `ca.get` |
| `labmitm://audit/recent` | `audit.list` |

`subscriptions/listen` on `labmitm://flows` notifies **URI only**; clients pull bodies with `mitm_flows_list`.

## Auth

MCP is bearer-only. Tokens are the same lab static bearer set as REST (`spec.management.auth.tokens`). No OAuth Protected Resource Metadata. No HTTP Basic.

## Compatibility promise

MCP tool names `mitm_*` are frozen; rename needs ADR + catalog change.

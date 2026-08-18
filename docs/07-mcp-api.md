# MCP API

Status: Proposed normative behavior
Owners: MCP, Application
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0004, 0006

Native management API is `/v1` + `POST /mcp`. Capability IDs and tool names are frozen in [docs/05-control-plane-and-parity.md](05-control-plane-and-parity.md). Protocol pin: [docs/adr/0006-pin-mcp-protocol-versions.md](adr/0006-pin-mcp-protocol-versions.md).

## Transport and pin

- SDK: `github.com/modelcontextprotocol/go-sdk v1.7.0`
- Protocol: `2026-07-28`
- Transport: Streamable HTTP `POST /mcp` on the management listener
- Optional: `labmitm mcp-stdio --config … --token-file …` (stdout = protocol, stderr = logs)
- `Stateless: true`
- Auth: bearer only
- Origin check: same as REST (**missing Origin allowed**; D15)
- Pin recorded in `internal/buildinfo` and `/v1/version`
- `spec.management.mcp.allowLegacyClients` default **false**. Integration-lab overlay sets `true` so MCPJungle (`mark3labs/mcp-go v0.48`) can register without a LabMITM patch.
- `subscriptions/listen` stays 2026-07-28 even when the pin is relaxed.

Tool input/output schemas are generated from the same Go request/response types as REST. MCP structured content is the operation result **without** the HTTP problem envelope; domain `code` is always present on errors.

Resources mirror GET representations. Clients without resource support use the `mitm_*` read tools.

## Tools (frozen)

Every `PARITY_REQUIRED` capability in [docs/05-control-plane-and-parity.md](05-control-plane-and-parity.md) has a `mitm_*` tool listed in that table. Do not add a REST control without adding the twin tool in the same PR.

Health live/ready, OpenAPI, UI assets, session/CSRF, `/v1/metrics`, mitmweb compat, and binary cert downloads (`application/x-pkcs12`) are **not** MCP tools. `mitm_ca_cert_get` returns PEM text.

## Resources (frozen)

| URI | Capability |
|---|---|
| `labmitm://capabilities` | `capabilities.get` |
| `labmitm://status` | `status.get` |
| `labmitm://schema/config` | `schema.get` |
| `labmitm://state` | `state.get` |
| `labmitm://flows` | `flows.list` |
| `labmitm://flows/{id}` | `flows.get` |
| `labmitm://audit/recent` | `audit.list` |

`subscriptions/listen` on `labmitm://flows` notifies **URI only**; clients pull bodies with `mitm_flows_list`.

## Auth

MCP is bearer-only. Basic is not accepted on `/mcp`. Tokens are the same lab static bearer set as REST. No OAuth Protected Resource Metadata.

## Compatibility promise

MCP tool names `mitm_*` are frozen; rename needs ADR + catalog change.

## Agent usage notes

Typical lab loop:

1. `mitm_status_get` / `mitm_ca_cert_get` to configure the system under test.
2. Optional `mitm_intercept_set` with a filter.
3. Drive the SUT.
4. `mitm_flows_wait` instead of sleeping.
5. `mitm_flow_get` / `mitm_flow_content_view` to assert.
6. `mitm_state_reset` between scenarios.

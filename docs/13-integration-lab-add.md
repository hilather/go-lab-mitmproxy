# Integration-lab Add

Status: Proposed normative behavior
Owners: Integration, Platform
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0005, 0006, 0012

LabMITM is a **new** mcp-integration-lab service (not a swap of an existing image). LAB-001 lands overlay examples in **this** repo. The compose/profile change is a follow-up PR in `hilather/mcp-integration-lab`.

labinfo catalog id is **`labmitm`**.

## Overlay files in this repo

| This repo | Lab destination | Role |
|---|---|---|
| `examples/labmitm.yaml` | `profiles/default/labmitm/bootstrap.yaml` | `allowLegacyClients: true`, `blockGlobal: false`, regular mode |
| `examples/mcpjungle/servers/labmitm.json` | `profiles/default/mcpjungle/servers/labmitm.json` | Filename matches JSON `name`. URL `http://labmitm:8081/mcp` |
| `examples/mcpjungle/groups/integration.json` | merge | **Append** `"labmitm"` to `included_servers` |
| `examples/labinfo/services-labmitm.yaml` | merge into `labinfo/services.yaml` | URLs + connection block |

## Ports (profile.env)

| Variable | Default | Container |
|---|---|---|
| `LABMITM_PROXY_PORT` | 18880 | 8080/tcp |
| `LABMITM_WEB_PORT` | 18081 | 8081/tcp |
| `LABMITM_SOCKS_PORT` | unset | optional 10800 |

Do not use host 8080 (gateway), 1080 (LabMail), or 18080 (LabDNS).

## Secrets

`mcplab secrets` must:

- `writeTokenIfMissing(secrets/labmitm-token, 0o644)` ≥256 bits
- Generate CA into `secrets/labmitm-ca/` (`labmitm-ca.pem`, `labmitm-ca-cert.pem`) if missing
- `stageLabinfoCreds` copies
- Registrar env `LABMITM_TOKEN`

## Compose fragment

Service name `labmitm`. Healthcheck HTTP `GET /v1/health/ready`. CA + token + bootstrap mounts. `read_only`, `cap_drop: ALL`, user `65532`.

## Smoke (lab follow-up)

1. Unauthenticated `GET /v1/flows` → 401.
2. `curl -x http://127.0.0.1:${LABMITM_PROXY_PORT} --cacert secrets/labmitm-ca/labmitm-ca-cert.pem http://labinfo:8080/` or an in-compose origin — **use an in-lab origin**, not the public Internet. Suggested: HTTP GET to LabMail’s management is wrong protocol; add a tiny `httptest` origin in smoke **or** GET LabDNS HTTP is none. **Frozen:** smoke origin is LabMITM onboarding `http://mitm.it/` through the proxy (served locally) asserting 200 and CA download path, plus `mitm_flows_wait` for that flow.
3. Bearer MCP `mitm_flows_list` via gateway contains the flow.

Do not require public HTTPS in CI.

## Docs the lab PR must update

- `AGENTS.md` new rule for LabMITM (YAML desired state, ephemeral flows, CA mount, MCP).
- `docs/architecture.md` service table + topology.
- `README.md` ports table.
- `CHANGELOG.md`.
- labinfo `connection` block: HTTP proxy endpoint, `http://host:port`, CA file path, no TLS to the proxy itself by default.

## Vendor pin

`internal/lab/vendor.go` pin LabMITM tag after first rc. Until then LAB-001 only ships examples.

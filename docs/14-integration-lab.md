# Integration-lab Overlay

Status: Proposed normative behavior
Owners: Integration, Platform
Last reviewed: 2026-08-18 (SWAP-001 + GA-001)
Related ADRs: 0005, 0006, 0007

This document is the bill of materials for adding LabMITM to `mcp-integration-lab`. SWAP-001 lands the overlay in **this** repo. The compose/image pin change is a **follow-on lab PR** after `v1.0.0-rc.1` of this repo (D18).

There is **no** predecessor service. Catalog id is **`labmitm`**. Do **not** claim the lab already runs LabMITM. 1.0 ships the appliance; lab compose-in is a follow-on.

## Overlay files in this repo

Copy these into `mcp-integration-lab` at the paths in the BOM. Do not invent a second schema.

| This repo | Lab destination | Role |
|---|---|---|
| [examples/labmitm.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/labmitm.yaml) | `profiles/default/labmitm/bootstrap.yaml` | Lab overlay. Published binds `:8888`/`:8088`. `allowLegacyClients: true` (D15). Recommended `allowHosts` (`*.lab` + compose DNS names). Bearer token `secretFile: /run/secrets/labmitm-token`. Not the DEP-001 compose-smoke file (`testdata/container/config.yaml`). |
| [examples/mcpjungle/servers/labmitm.json](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/mcpjungle/servers/labmitm.json) | `profiles/default/mcpjungle/servers/labmitm.json` | Filename must match JSON `name` (lab AGENTS.md rule 8). URL is `http://labmitm:8088/mcp`. |
| [examples/mcpjungle/groups/integration.json](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/mcpjungle/groups/integration.json) | `profiles/default/mcpjungle/groups/integration.json` | **Append** `"labmitm"` to `included_servers`. Stage 4 is not “add a JSON file” alone. |
| [examples/labinfo/services-labmitm.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/labinfo/services-labmitm.yaml) | merge into `profiles/default/labinfo/services.yaml` | Catalog id is `labmitm`. Adds `/v1` + MCP. |
| [examples/compose.smoke.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/compose.smoke.yaml) | container-local smoke only | DEP-001 smoke. Do not mount `examples/labmitm.yaml` as the smoke config unless the smoke compose mints and mounts `labmitm-token` at 0o644. |

Acceptance twin in this repo: `TestLabOverlayExample` / `TestLabMCPJungleExamples` / `TestLabinfoSnippetKeepsCatalogID` in `internal/config/example_overlay_test.go`.

## Current HTTP intercept contract

`mcp-integration-lab` today has **no** mitmproxy service and **no** mitmproxy HTTP API consumer. Lab HTTP debugging is either “hope the app logs” or “run community mitmproxy next to the family,” which breaks the GitOps / MCP / hardened-container contract (`mcp-integration-lab` `AGENTS.md` rule 8: new services expose MCP, take YAML, run unprivileged).

## Proposed compose fragment (follow-on lab PR)

Service name is `labmitm`. Host ports `${LABMITM_PROXY_PORT:-18888}:8888` and `${LABMITM_WEB_PORT:-18088}:8088`. Overlay YAML sets `listeners.*.address: ":8888"` / `":8088"`, `allowLegacyClients: true`, recommended `allowHosts` (`*.lab`, compose DNS names), `tls.intercept` as the profile chooses.

`--management-listen` defaults to `off` on the binary. The lab command **must** pass `--management-listen=:8088` so healthcheck, REST, MCP, and the SPA bind.

```yaml
  labmitm:
    image: ghcr.io/hilather/labmitm:<pin>
    command: ["serve", "--config=/etc/labmitm/config.yaml", "--management-listen=:8088"]
    networks: [default]
    ports:
      - "${LABMITM_PROXY_PORT:-18888}:8888/tcp"
      - "${LABMITM_WEB_PORT:-18088}:8088/tcp"
    volumes:
      - ${MCPLAB_PROFILE_DIR:-./profiles/default}/labmitm/bootstrap.yaml:/etc/labmitm/config.yaml:ro
      - ./secrets/labmitm-token:/run/secrets/labmitm-token:ro
    read_only: true
    tmpfs: ["/tmp"]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    user: "65532:65532"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "/labmitm", "healthcheck", "--url=http://127.0.0.1:8088/v1/health/ready"]
      interval: 5s
      timeout: 3s
      retries: 12
      start_period: 3s
```

`mcp-integration-lab` `AGENTS.md` rule 5: composed services publish on all interfaces. Standalone defaults stay loopback (D10). The lab overlay is the place that binds `:8888`/`:8088`. Bind-mounted secrets must be **0o644** (UID 65532).

Image pin and Dockerfile land in DEP-001 (this repo). The compose/image pin in the lab is a follow-up. This fragment is the compose contract, not an in-tree image.

## Bill of materials

Stage 4 is not “add a JSON file”; token + tool-group registration are mandatory.

| File / surface | Today | Swap must |
|---|---|---|
| `docker-compose.yaml` service `labmitm` | missing | LabMITM image, `serve --config` + `--management-listen=:8088`, secret file mount, HTTP healthcheck |
| `internal/lab/secrets.go` | no labmitm token | **Add** `writeTokenIfMissing(secrets/labmitm-token, 0o644)` (≥256 bits, same helper/mode as `labdns-token`) and `stageLabinfoCreds` copy. UID 65532 must read the bind-mount. |
| `profiles/default/labmitm/bootstrap.yaml` | missing | Copy [examples/labmitm.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/labmitm.yaml) (`allowLegacyClients: true`, published binds, recommended `allowHosts`) |
| `profiles/default/labinfo/services.yaml` id `labmitm` | missing | Catalog id **`labmitm`**; add `/v1` + MCP URL; add bearer credential file |
| labinfo compose env | no `LABMITM_*` | Add `LABMITM_PROXY_PORT` (default 18888), `LABMITM_WEB_PORT` (default 18088) |
| `docker-compose.yaml` `registrar` env | `LABDNS_TOKEN`, `LABLDAP_TOKEN`, `LABTACACS_TOKEN`, `LABINFO_TOKEN`, `LABMAIL_TOKEN` | Add `LABMITM_TOKEN` (same pattern as LabDNS) |
| `internal/lab/register.go` / `smoke.go` | no mitm MCP | Interpolate `${LABMITM_TOKEN}`; optional `mitm_flows_wait` smoke |
| `profiles/default/mcpjungle/servers/labmitm.json` | missing | `http://labmitm:8088/mcp` + `${LABMITM_TOKEN}` |
| `profiles/default/mcpjungle/groups/integration.json` | `included_servers`: labdns, labldap, labtacacs, labinfo, labmail | **Append** `"labmitm"` (AGENTS.md rule 8) |
| `AGENTS.md` | no LabMITM rule | Add: YAML overlay, bearer-only, published binds, `allowHosts`, unauthenticated data plane |
| `docs/architecture.md` | no LabMITM row | LabMITM MCP `http://labmitm:8088/mcp`; healthcheck plane HTTP ready |
| `CHANGELOG.md` | no LabMITM | Image add + MCP |

### labinfo snippet

Copy from [examples/labinfo/services-labmitm.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/labinfo/services-labmitm.yaml):

```yaml
services:
  - id: labmitm
    name: HTTP intercept (LabMITM)
    description: Laboratory HTTP(S) intercepting forward proxy with a flow-inspector UI, native /v1 REST, and MCP. Captured flows are wiped on restart. Compose-in is a follow-on lab PR.
    urls:
      - name: Web UI
        url: http://${LAB_PUBLIC_HOST}:${LABMITM_WEB_PORT}/
      - name: REST API (native /v1)
        url: http://${LAB_PUBLIC_HOST}:${LABMITM_WEB_PORT}/v1
      - name: MCP endpoint
        url: http://${LAB_PUBLIC_HOST}:${LABMITM_WEB_PORT}/mcp
      - name: CA certificate
        url: http://${LAB_PUBLIC_HOST}:${LABMITM_WEB_PORT}/v1/ca
    note: "HTTP/1.1 forward proxy (no Proxy-Authorization): ${LAB_PUBLIC_HOST}:${LABMITM_PROXY_PORT}. Point systems under test at it as HTTP_PROXY / HTTPS_PROXY. Install GET /v1/ca into the SUT trust store for HTTPS intercept. Generate-mode CA rotates on restart."
    credential:
      file: /run/lab-secrets/labmitm-token
      usage: "HTTP header 'Authorization: Bearer <token>' for native /v1, MCP, and the flow-inspector UI; on the lab host: secrets/labmitm-token"
    connection:
      endpoints:
        - name: HTTP proxy
          protocol: http-proxy
          address: ${LAB_PUBLIC_HOST}:${LABMITM_PROXY_PORT}
          note: unauthenticated HTTP/1.1 absolute-form + CONNECT; do not publish without a network boundary
        - name: MCP (streamable HTTP)
          protocol: mcp-streamable-http
          address: http://${LAB_PUBLIC_HOST}:${LABMITM_WEB_PORT}/mcp
          note: bearer only; gateway interpolates LABMITM_TOKEN
      parameters:
        auth: "proxy data plane is unauthenticated; management is bearer-only (no HTTP Basic)"
        tls: "HTTPS intercept uses an in-process lab CA; clients must trust GET /v1/ca"
        hosts: "allowHosts includes *.lab and compose DNS names"
      credentials:
        - name: labmitm-token
          file: /run/lab-secrets/labmitm-token
          usage: "HTTP header 'Authorization: Bearer <token>' for native /v1 and MCP; on the lab host: secrets/labmitm-token"
```

`stageLabinfoCreds` in `internal/lab/secrets.go` must copy `secrets/labmitm-token` into `secrets/labinfo-creds/labmitm-token` so the catalog file resolves.

### MCPJungle server JSON

Copy from [examples/mcpjungle/servers/labmitm.json](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/mcpjungle/servers/labmitm.json). Registrar env must include `LABMITM_TOKEN` (same pattern as `LABDNS_TOKEN` in `internal/lab/register.go` `loadTokens` + compose `registrar`).

```json
{
  "name": "labmitm",
  "transport": "streamable_http",
  "description": "Laboratory HTTP(S) intercepting proxy (LabMITM): captured flows over REST /v1, wait/resume/drop/replay, plan/apply/reset. Compose-in is a follow-on lab PR.",
  "url": "http://labmitm:8088/mcp",
  "bearer_token": "${LABMITM_TOKEN}"
}
```

`groups/integration.json` `included_servers` becomes `["labdns", "labldap", "labtacacs", "labinfo", "labmail", "labmitm"]`.

## Operator warnings

- Publishing `:8888` without `allowHosts` is an operator choice; the lab overlay **should** set `allowHosts` to `*.lab` / compose DNS names.
- The proxy data plane is unauthenticated (D17). Do not publish without a network boundary.
- Generate-mode CA rotates on restart; clients must re-download `GET /v1/ca`.
- UI / README banner: lab-only; uninstall the lab CA after use.

## Rollout in mcp-integration-lab

Feature flag is the image pin, not a runtime flag:

| Stage | Action | Rollback |
|---|---|---|
| 0 | LabMITM rc exists; lab has no intercept service | n/a |
| 1 | Add `profiles/default/labmitm/bootstrap.yaml` | revert files |
| 2 | Add compose service `labmitm`; add `secrets/labmitm-token` at **0o644**; HTTP healthcheck | delete service + secret |
| 3 | `make smoke` — new optional `labmitmScenario` (proxy GET + 401 on `/v1/flows` + bearer list) | same |
| 4 | Register MCP: `servers/labmitm.json` **and** `groups/integration.json` + `LABMITM_TOKEN` in registrar env; `allowLegacyClients: true` | un-register server JSON + drop group entry |
| 5 | Rewrite AGENTS.md and `docs/architecture.md` | |

LabMITM is stateless. Rolling back is an image + command-line revert. Captured flows are lost on any restart either way.

## SWAP-001 checklist (in this repo)

Must name:

- catalog id `labmitm`
- registrar `LABMITM_TOKEN`
- `integration.json` append `"labmitm"`
- overlay `allowLegacyClients: true` + published binds + recommended `allowHosts`
- healthcheck exec form against `GET /v1/health/ready`
- `--management-listen=:8088` on the lab command (binary default is `off`)
- do **not** claim the lab already runs LabMITM

Shipped here:

- Full file-level BOM above
- `examples/labmitm.yaml` with published binds, `allowLegacyClients: true`, recommended `allowHosts`
- labinfo snippet (`examples/labinfo/services-labmitm.yaml`)
- `examples/mcpjungle/servers/labmitm.json` + group append
- D18 (catalog id `labmitm`; compose-in is a follow-on) recorded

Not in this PR: the mcp-integration-lab pin change (lab follow-up).

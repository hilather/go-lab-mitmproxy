# Integration-lab Overlay

Status: Proposed normative behavior
Owners: Integration, Platform
Last reviewed: 2026-08-23
Related ADRs: 0005, 0006, 0007

This document is the bill of materials for adding LabMITM to `mcp-integration-lab`. SWAP-001 lands the overlay in **this** repo. The first Git tag is **v1.1.0**. Compose-in is still a **follow-on lab PR** (D18).

There is **no** predecessor service. Catalog id is **`labmitm`**. Do **not** claim the lab already runs LabMITM. v1.1.0 is the pin; lab compose-in is a follow-on.

## Overlay files in this repo

Copy these into `mcp-integration-lab` at the paths in the BOM. Do not invent a second schema.

| This repo | Lab destination | Role |
|---|---|---|
| [examples/labmitm.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/labmitm.yaml) | `profiles/default/labmitm/bootstrap.yaml` | Lab overlay. Published binds `:8888`/`:8088`. `allowLegacyClients: true` (D15). Recommended `allowHosts` (`*.lab`, `labdns`, `labinfo`, `maildev`, `mcpjungle`, `control`, `taclab`; HTTP-useful compose DNS). `nfs` / `directory` are comments only. Exact Origins (no `"*"`; loopback already allowed). Bearer token `secretFile: /run/secrets/labmitm-token`. Not the DEP-001 compose-smoke file (`testdata/container/config.yaml`). |
| [examples/mcpjungle/servers/labmitm.json](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/mcpjungle/servers/labmitm.json) | `profiles/default/mcpjungle/servers/labmitm.json` | Filename must match JSON `name` (lab AGENTS.md rule 8). URL is `http://labmitm:8088/mcp`. |
| [examples/mcpjungle/groups/integration.json](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/mcpjungle/groups/integration.json) | `profiles/default/mcpjungle/groups/integration.json` | **Append** `"labmitm"` to `included_servers`. PR-L2 is not “add a JSON file” alone. |
| [examples/labinfo/services-labmitm.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/labinfo/services-labmitm.yaml) | merge into `profiles/default/labinfo/services.yaml` | Catalog id is `labmitm`. Adds `/v1` + MCP. |
| [examples/compose.smoke.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/compose.smoke.yaml) | container-local smoke only | DEP-001 smoke. Do not mount `examples/labmitm.yaml` as the smoke config unless the smoke compose mints and mounts `labmitm-token` at 0o644. |

Acceptance twin in this repo: `TestLabOverlayExample` / `TestLabMCPJungleExamples` / `TestLabinfoSnippetKeepsCatalogID` in `internal/config/example_overlay_test.go`.

## Current HTTP intercept contract

`mcp-integration-lab` today has **no** mitmproxy service and **no** mitmproxy HTTP API consumer. Lab HTTP debugging is either “hope the app logs” or “run community mitmproxy next to the family,” which breaks the GitOps / MCP / hardened-container contract (`mcp-integration-lab` `AGENTS.md` rule 8: new services expose MCP, take YAML, run unprivileged).

## Proposed compose fragment (follow-on lab PR)

Service name is `labmitm`. Host ports `${LABMITM_PROXY_PORT:-18888}:8888` and `${LABMITM_WEB_PORT:-18088}:8088`. Overlay YAML sets `listeners.*.address: ":8888"` / `":8088"`, `allowLegacyClients: true`, recommended `allowHosts` (`*.lab`, `labdns`, `labinfo`, `maildev`, `mcpjungle`, `control`, `taclab`), `tls.intercept` as the profile chooses.

`--management-listen` defaults to `off` on the binary. The lab command **must** pass `--management-listen=:8088` so healthcheck, REST, MCP, and the SPA bind.

Pin strategy is the lab `vendor.go` Git tag **v1.1.0** plus a local compose build (`build.context: ./third_party/go-lab-mitmproxy`, image `labmitm:local`) — the LabDNS / LabMail sibling pattern. Not a GHCR digest.

Networks are **`[default, shared]`**. Dual-network is reachability, not TLS intercept. Overlay intercept stays HTTPS `:443`. LabLDAP / TacLab TLS is tunnel-not-decrypt.

```yaml
  # LabMITM intercepting HTTP(S) forward proxy.
  # Binary --management-listen defaults to off (unlike LabDNS, whose YAML
  # bind is enough). Do not copy LabDNS command: ["serve", "--config=..."]
  # or HEALTHCHECK fails closed.
  # Reload: `make reload APP=labmitm` (wipes captured flows; generate-mode
  # CA rotates).
  labmitm:
    build:
      context: ./third_party/go-lab-mitmproxy
    image: labmitm:local
    command: ["serve", "--config=/etc/labmitm/config.yaml", "--management-listen=:8088"]
    networks: [default, shared]
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

Dockerfile and hardened image contract land in DEP-001 (this repo). The lab compose-in pin is the follow-on PR (D18). This fragment is the compose contract.

## Bill of materials

PR-L2 is not “add a JSON file”; token + tool-group registration are mandatory and must land **before** smoke (`mitm_flows_wait` requires registration).

Pin strategy: lab `vendor.go` Git tag **v1.1.0** + local build. Not a GHCR digest. `allowHosts` is the HTTP-useful compose DNS list (`*.lab`, `labdns`, `labinfo`, `maildev`, `mcpjungle`, `control`, `taclab`). `nfs` / `directory` stay comments only. Origin allowlist is exact Origins — no `"*"`. Loopback Origins are already allowed (any port). Missing Origin is allowed (MCPJungle, curl). Remote inspector needs `http://<LAB_PUBLIC_HOST>:${LABMITM_WEB_PORT}` in bootstrap; LabMITM YAML does not interpolate `${VAR}`.

| File / surface | Today | Swap must |
|---|---|---|
| lab `vendor.go` dest `third_party/go-lab-mitmproxy` | missing | Pin Git tag **v1.1.0**; local compose `build.context` → image `labmitm:local`. Not a GHCR digest |
| `docker-compose.yaml` service `labmitm` | missing | Local build as above, `serve --config` + `--management-listen=:8088`, networks `[default, shared]`, secret file mount, HTTP healthcheck |
| `internal/lab/secrets.go` | no labmitm token | **Add** `writeTokenIfMissing(secrets/labmitm-token, 0o644)` (≥256 bits, same helper/mode as `labdns-token`) and `stageLabinfoCreds` copy. UID 65532 must read the bind-mount. |
| `profiles/default/labmitm/bootstrap.yaml` | missing | Copy [examples/labmitm.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/labmitm.yaml) (`allowLegacyClients: true`, published binds, recommended `allowHosts`) |
| `profiles/default/labinfo/services.yaml` id `labmitm` | missing | Catalog id **`labmitm`**; add `/v1` + MCP URL; add bearer credential file |
| labinfo compose env | no `LABMITM_*` | Add `LABMITM_PROXY_PORT` (default 18888), `LABMITM_WEB_PORT` (default 18088) |
| `docker-compose.yaml` `registrar` env | `LABDNS_TOKEN`, `LABLDAP_TOKEN`, `LABTACACS_TOKEN`, `LABINFO_TOKEN`, `LABMAIL_TOKEN` | Add `LABMITM_TOKEN` (same pattern as LabDNS) |
| `internal/lab/register.go` / `smoke.go` | no mitm MCP | Interpolate `${LABMITM_TOKEN}`; `mitm_flows_wait` smoke **after** MCP registration (PR-L3) |
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
    note: "HTTP/1.1 forward proxy (no Proxy-Authorization): ${LAB_PUBLIC_HOST}:${LABMITM_PROXY_PORT}. Point systems under test at it as HTTP_PROXY / HTTPS_PROXY. Install GET /v1/ca into the SUT trust store for HTTPS intercept. Generate-mode CA rotates on restart. Origin allowlist is exact Origins only (loopback already allowed; no \"*\"). Remote inspector needs http://${LAB_PUBLIC_HOST}:${LABMITM_WEB_PORT} in bootstrap."
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
        hosts: "allowHosts includes *.lab and compose DNS names (labdns, labinfo, maildev, mcpjungle, control, taclab)"
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

- Publishing `:8888` without `allowHosts` is an operator choice; the lab overlay **should** set `allowHosts` to `*.lab`, `labdns`, `labinfo`, `maildev`, `mcpjungle`, `control`, `taclab`. `nfs` / `directory` stay comments only.
- The proxy data plane is unauthenticated (D17). Do not publish without a network boundary.
- Generate-mode CA rotates on restart; clients must re-download `GET /v1/ca`.
- Origin allowlist is exact Origins only (no `"*"`). Loopback Origins are already allowed. Remote inspector needs `http://<LAB_PUBLIC_HOST>:${LABMITM_WEB_PORT}` in bootstrap.
- Dual-network (`default` + `shared`) is reachability, not TLS intercept. Overlay intercept stays HTTPS `:443`. LabLDAP / TacLab TLS is tunnel-not-decrypt.
- UI / README banner: lab-only; uninstall the lab CA after use.

## Rollout in mcp-integration-lab

Feature flag is the vendor pin + compose service, not a runtime flag. Smoke is **after** MCP: `mitm_flows_wait` requires MCPJungle registration. Lockstep L1→L2→L3 (unlike the original optional pre-MCP smoke row).

| Stage | Action | Rollback |
|---|---|---|
| 0 | LabMITM v1.1.0 exists; lab has no intercept service | n/a |
| 1 (PR-L1) | Vendor pin v1.1.0 + `profiles/default/labmitm/bootstrap.yaml` + compose service + secrets/labmitm-token 0o644 + published ports | delete service, secret, vendor dest, overlay copy |
| 2 (PR-L2) | MCPJungle servers/labmitm.json AND groups/integration.json + LABMITM_TOKEN + labinfo catalog | un-register server JSON, drop group entry |
| 3 (PR-L3) | make smoke labmitmScenario (401 + bearer list + host :18888 proxy GET + mitm_flows_wait) + reload + AGENTS/architecture/CHANGELOG/Pages | revert |

MCP wait makes smoke a post-registration check. `make up && make smoke` is the acceptance gate.

LabMITM is stateless. Rolling back is a vendor + command-line revert. Captured flows are lost on any restart either way. `make reload APP=labmitm` wipes captured flows and rotates a generate-mode CA.

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

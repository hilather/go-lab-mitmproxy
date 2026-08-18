# Integration-lab Overlay

Status: Proposed normative behavior
Owners: Integration, Platform
Last reviewed: 2026-08-18 (FND-001)
Related ADRs: 0005, 0006, 0007

This document is the bill of materials for adding LabMITM to `mcp-integration-lab`. The compose/image pin change is a **follow-on lab PR** after `v1.0.0-rc.1` of this repo (D18). SWAP-001 (named slice inside PR 14) lands the overlay examples this lab will copy.

There is **no** predecessor service. Catalog id is **`labmitm`**. Do not claim the lab already runs LabMITM.

## Current HTTP intercept contract

`mcp-integration-lab` today has **no** mitmproxy service and **no** mitmproxy HTTP API consumer. Lab HTTP debugging is either “hope the app logs” or “run community mitmproxy next to the family,” which breaks the GitOps / MCP / hardened-container contract (`mcp-integration-lab` `AGENTS.md` rule 8: new services expose MCP, take YAML, run unprivileged).

## Proposed compose fragment (follow-on lab PR)

Service name is `labmitm`. Host ports `${LABMITM_PROXY_PORT:-18888}:8888` and `${LABMITM_WEB_PORT:-18088}:8088`. Overlay YAML sets `listeners.*.address: ":8888"` / `":8088"`, `allowLegacyClients: true`, recommended `allowHosts` (`*.lab`, compose DNS names), `tls.intercept` as the profile chooses.

```yaml
  labmitm:
    image: ghcr.io/hilather/labmitm:<pin>
    command: ["serve", "--config=/etc/labmitm/config.yaml"]
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

`mcp-integration-lab` `AGENTS.md` rule 5: composed services publish on all interfaces. Standalone defaults stay loopback (D10). The lab overlay is the place that binds `:8888`/`:8088`.

## Bill of materials (SWAP-001 in this repo)

| File / surface | SWAP-001 must |
|---|---|
| `examples/labmitm.yaml` | Published binds `:8888`/`:8088`, `allowLegacyClients: true`, recommended `allowHosts` |
| `examples/mcpjungle/servers/labmitm.json` | `url: http://labmitm:8088/mcp`, `bearer_token: ${LABMITM_TOKEN}` |
| `examples/mcpjungle/groups/integration.json` | Append `"labmitm"` |
| `examples/labinfo/services-labmitm.yaml` | Catalog id **`labmitm`** |
| `examples/compose.smoke.yaml` | Container-local smoke (DEP-001 / SWAP-001) |
| `docs/14-integration-lab.md` | This BOM |

Follow-on lab PR (out of scope for go-lab-mitmproxy 1.0 GA):

1. Vendor `go-lab-mitmproxy` (or build from a pin) in `mcp-integration-lab`.
2. Add compose service `labmitm` with the ports above.
3. Profile env + labinfo catalog id `labmitm` + MCPJungle `servers/labmitm.json`.
4. `mcplab secrets` stages `secrets/labmitm-token`.
5. Overlay YAML as above.

## Operator warnings

- Publishing `:8888` without `allowHosts` is an operator choice; the lab overlay **should** set `allowHosts` to `*.lab` / compose DNS names.
- The proxy data plane is unauthenticated (D17). Do not publish without a network boundary.
- Generate-mode CA rotates on restart; clients must re-download `GET /v1/ca`.
- UI / README banner: lab-only; uninstall the lab CA after use.

## SWAP-001 checklist (in this repo)

Must name:

- catalog id `labmitm`
- registrar `LABMITM_TOKEN`
- `integration.json` append `"labmitm"`
- overlay `allowLegacyClients: true` + published binds + recommended `allowHosts`
- healthcheck exec form against `GET /v1/health/ready`
- do **not** claim the lab already runs LabMITM

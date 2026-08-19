# Deployment

Status: Proposed normative behavior
Owners: Platform, Operations
Last reviewed: 2026-08-18 (MCP-001)
Related ADRs: 0001, 0003

Dockerfile, compose, and `scripts/test-container.sh` land in DEP-001 (PR 12). This document freezes the contract so later PRs do not invent ports or image posture.

## CLI

```text
labmitm serve --config=/etc/labmitm/config.yaml
              [--proxy-listen ADDR] [--management-listen ADDR|off]
              [--shutdown-timeout 5s] [--pid-file /tmp/labmitm.pid]
labmitm validate --config=...
labmitm canonicalize --config=... [--format yaml|json]
labmitm healthcheck --url=http://127.0.0.1:8088/v1/health/ready
labmitm mcp-stdio --config=... --token-file=...
labmitm version
labmitm help
```

Flag semantics (LabMail-shaped; **no** `serve --token-file`):

| Flag | Commands | Behavior |
|---|---|---|
| `--config` | `serve`, `validate`, `canonicalize`, `mcp-stdio` | Required. Bootstrap path. Never written. |
| `--proxy-listen` | `serve` | Override `spec.listeners.proxy.address`. Empty = YAML. |
| `--management-listen` | `serve` | Override management bind. `off` / `none` / `-` leaves it unbound. |
| `--token-file` | `mcp-stdio` **only** (required) | Verified before protocol starts. |
| `--shutdown-timeout` | `serve` | Default `5s`. |
| `--pid-file` | `serve` | Written only after both required listeners bind (or management explicitly off). |

`serve` loads → compile → bind **proxy** → bind management → write pid file. Invalid bootstrap does **not** bind proxy or management.

`SIGTERM`/`SIGINT`: stop proxy accept, drain sessions (deadline), then HTTP, then `store.Wipe` spill files. `SIGUSR1` unused (no chaos).

`labmitm send` / `labmitm request` are **not** shipped.

PROXY-001 implements `serve` (proxy bind only; `--management-listen` defaults to `off`; no `--token-file`). MCP-001 implements `mcp-stdio` (`--config` and `--token-file` required; stdout is protocol, stderr is logs) and mounts `POST /mcp` on the management listener. `healthcheck` remains unimplemented. Invalid bootstrap binds nothing.

## Hardened container

Dockerfile is LabMail-shaped (Go 1.26.6-alpine → scratch). **No Node stage in PR 12** — `internal/web` embeds committed `dist/` or LabMail-style `stub/` from PR 8. PR 13’s `make web-build` copies `web/dist` into `internal/web/dist` (host/CI), not a Docker Node stage.

```
# build stage copies /etc/ssl/certs/ca-certificates.crt (required)
USER 65532:65532
EXPOSE 8888/tcp 8088/tcp
ENTRYPOINT ["/labmitm"]
CMD ["serve", "--config=/etc/labmitm/config.yaml"]
HEALTHCHECK CMD ["/labmitm", "healthcheck", "--url=http://127.0.0.1:8088/v1/health/ready"]
```

Posture:

- Image `ghcr.io/hilather/labmitm` (`:local` for compose builds, digest-pin in GitOps)
- Non-root UID `65532:65532`
- scratch/static, read-only root
- `cap_drop: ALL`, `no-new-privileges:true`
- tmpfs `/tmp` (optional spill under `/tmp/labmitm-spill`)
- no shell, no Docker socket
- Image does **not** contain a lab MITM CA key
- Image **must** copy `/etc/ssl/certs/ca-certificates.crt` so `x509.SystemCertPool()` is non-empty

DEP-001 acceptance: file exists, `SystemCertPool` non-empty in the running image, container smoke does HTTPS intercept against a fixture origin.

## Reference compose

Smoke compose publishes `8888` and `8088` (container-local test, not the production standalone default) and mounts a token file. Also `examples/compose.smoke.yaml` (DEP-001):

```yaml
services:
  labmitm:
    image: ghcr.io/hilather/labmitm:local
    command: ["serve", "--config=/etc/labmitm/config.yaml"]
    ports:
      - "8888:8888/tcp"
      - "8088:8088/tcp"
    volumes:
      - ./labmitm.yaml:/etc/labmitm/config.yaml:ro
      - ./secrets/labmitm-token:/run/secrets/labmitm-token:ro
    read_only: true
    tmpfs: ["/tmp"]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    user: "65532:65532"
    restart: unless-stopped
    networks: [default]
    healthcheck:
      test: ["CMD", "/labmitm", "healthcheck", "--url=http://127.0.0.1:8088/v1/health/ready"]
      interval: 5s
      timeout: 3s
      retries: 12
      start_period: 3s
```

`make test-container` asserts UID 65532, `CapEff=0`, Apache-2.0 label, exec-form HTTP ready, no `/bin/sh`, read-only root, **`/etc/ssl/certs/ca-certificates.crt` present and `x509.SystemCertPool` non-empty**, then `curl --proxy` a local origin with `Authorization: Bearer` against `/v1/flows`, plus an HTTPS intercept fixture.

## Compatibility promise

Standalone defaults stay loopback `127.0.0.1:8888` / `127.0.0.1:8088`. Lab overlay publishes `:8888` / `:8088`. Host ports when composed later: `18888` / `18088`.

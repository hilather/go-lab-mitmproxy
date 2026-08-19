# Deployment

Status: Proposed normative behavior
Owners: Platform, Operations
Last reviewed: 2026-08-19 (DEP-001 + UI-001)
Related ADRs: 0001, 0003

DEP-001 shipped the hardened image, `examples/compose.smoke.yaml`, and `scripts/test-container.sh`. Ports and image posture stay frozen here. This document freezes the contract so later PRs do not invent ports or image posture.

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

PROXY-001 implements `serve` (proxy bind; `--management-listen` defaults to `off`; no `--token-file`). MCP-001 implements `mcp-stdio` (`--config` and `--token-file` required; stdout is protocol, stderr is logs) and mounts `POST /mcp` on the management listener. OBS-001 implements `labmitm healthcheck --url=http://127.0.0.1:8088/v1/health/ready`. DEP-001 wires `--proxy-listen`, `--management-listen ADDR|off`, `--shutdown-timeout` (default 5s), and `--pid-file`, plus the hardened image, compose smoke, and `scripts/test-container.sh`. Invalid bootstrap binds nothing. Metrics scrape listen defaults to `127.0.0.1:9090` (empty disables).

## Hardened container

Dockerfile is LabMail-shaped (Go 1.26.6-alpine → scratch). **No Node stage in PR 12** — UI-001 added `make web-build` (Node **22.14.0**) which copies `web/dist` into `internal/web/dist` for `go:embed` on the host/CI, not a Docker Node stage. UI contract (pages, EventSource + 3s poll, no fuzzer/exploit/repeater): [docs/01-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/01-architecture.md#embedded-operator-ui). `spec.ui.enabled: false` 404s `/` and keeps REST/MCP. SEC-001’s image fixture is `testdata/container/` (`mode: bearer` plus a ≥256-bit token file; not `dev-loopback-unauth`).

```
# build stage copies /etc/ssl/certs/ca-certificates.crt (required)
USER 65532:65532
EXPOSE 8888/tcp 8088/tcp
ENTRYPOINT ["/labmitm"]
CMD ["serve", "--config=/etc/labmitm/config.yaml", "--management-listen=:8088"]
HEALTHCHECK CMD ["/labmitm", "healthcheck", "--url=http://127.0.0.1:8088/v1/health/ready"]
```

`serve --management-listen` defaults to `off` (proxy-only). The image `CMD` therefore passes `--management-listen=:8088` so HEALTHCHECK and authenticated `/v1` work.

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

Smoke compose publishes `8888` and `8088` (container-local test, not the production standalone default) and mounts a token file. Copyable smoke file: [examples/compose.smoke.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/compose.smoke.yaml). The smoke bootstrap is [testdata/container/config.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/testdata/container/config.yaml) (`mode: bearer`, published binds `:8888`/`:8088`). Bind-mounted secrets are **0o644** (UID 65532). Healthcheck is HTTP ready (exec form). Scratch has no `node`. There is no `serve --token-file`.

```yaml
services:
  labmitm:
    image: ghcr.io/hilather/labmitm:local
    build:
      context: ..
    command: ["serve", "--config=/etc/labmitm/config.yaml", "--management-listen=:8088"]
    ports:
      - "8888:8888/tcp"
      - "8088:8088/tcp"
    volumes:
      - ../testdata/container/config.yaml:/etc/labmitm/config.yaml:ro
      - ../testdata/container/token:/etc/labmitm/token:ro
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    user: "65532:65532"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "/labmitm", "healthcheck", "--url=http://127.0.0.1:8088/v1/health/ready"]
      interval: 10s
      timeout: 3s
      retries: 3
```

`make test-container` (`scripts/test-container.sh`) builds the image, asserts UID `65532`, `CapEff=0`, Apache-2.0 label, exec-form HTTP ready healthcheck, no `/bin/sh` or busybox, read-only root, **`/etc/ssl/certs/ca-certificates.crt` present and `x509.SystemCertPool` non-empty**, then `curl --proxy` a local origin with `Authorization: Bearer` against `/v1/flows`, plus an HTTPS intercept fixture. It parses `examples/compose.smoke.yaml` with `docker compose config` when the plugin is present. Docker is required; the script fails closed if the daemon is missing.

## Compatibility promise

Standalone defaults stay loopback `127.0.0.1:8888` / `127.0.0.1:8088`. Lab overlay publishes `:8888` / `:8088`. Host ports when composed later: `18888` / `18088`.

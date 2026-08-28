# Deployment

Status: Proposed normative behavior
Owners: Platform, Operations
Last reviewed: 2026-08-28 (D51' residual)
Related ADRs: 0001, 0003, 0010

DEP-001 shipped the hardened image, `examples/compose.smoke.yaml`, and `scripts/test-container.sh`. Ports and image posture stay frozen here. A `v*` tag is refused unless [`.github/workflows/release.yml`](https://github.com/hilather/go-lab-mitmproxy/blob/main/.github/workflows/release.yml) `tag-gate` sees required CI green on that SHA. Current notes: [docs/releases/v1.2.0.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/releases/v1.2.0.md). Untagged 1.0 notes remain [docs/releases/v1.0.0-rc.1.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/releases/v1.0.0-rc.1.md). The lab overlay YAML is [examples/labmitm.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/labmitm.yaml) (SWAP-001; published binds, `allowLegacyClients: true`). Do not mount that overlay as the smoke config without a 0o644 `labmitm-token`.

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

`make test-container` (`scripts/test-container.sh`) builds the image, asserts UID `65532`, `CapEff=0`, Apache-2.0 label, exec-form HTTP ready healthcheck, no `/bin/sh` or busybox, read-only root, **`/etc/ssl/certs/ca-certificates.crt` present and `x509.SystemCertPool` non-empty**, then `curl --proxy` a local origin with `Authorization: Bearer` against `/v1/flows`, plus an HTTPS intercept fixture. It parses `examples/compose.smoke.yaml` with `docker compose config` when the plugin is present. Docker is required; the script fails closed if the daemon is missing. **`make test-container` never requires `NET_ADMIN`.** Optional `make test-container-originaldest` asserts the orig-dest overlay contract and **skips** live REDIRECT when the host cannot grant `NET_ADMIN`.

## Original-destination (Linux REDIRECT)

**Default off.** 1.0 processes do not bind `:8890`. Opt-in `spec.listeners.originalDestination.enabled` (Reset-only) binds `127.0.0.1:8890` by default (D38). Empty address materializes that loopback, not `:8890`. **TPROXY is rejected** (`tproxy` stays reserved). The default image stays `USER 65532:65532` and `cap_drop: ALL`. `EXPOSE` stays `8888/tcp 8088/tcp` — the image does not publish orig-dest.

**Publishing `8890` is not transparent (D50).** Docker `-p 8890:8890` / host DNAT to the published port does not preserve the pre-DNAT dest on the in-container socket. `SO_ORIGINAL_DST` then sees the container dest (often `:8890`) → direct-connect close or hairpin.

Supported topologies only:

1. Shared netns: SUT uses `network_mode: service:labmitm`. A sidecar (not the appliance) has `CAP_NET_ADMIN` and installs REDIRECT. labmitm stays unprivileged.
2. Host network: labmitm `--network host` (still UID 65532) + **host** iptables REDIRECT to `127.0.0.1:8890`.

**Not supported:** Windows/macOS orig-dest; TPROXY / `IP_TRANSPARENT` / `CAP_NET_ADMIN` on the appliance; treating a published `8890` as transparent mode.

Copyable overlay: [examples/compose.originaldest.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/compose.originaldest.yaml). Bootstrap: [testdata/container/originaldest.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/testdata/container/originaldest.yaml). Do not redirect 8088, 8888, 8890, or 9090. **REDIRECT must not apply to the appliance UID `65532`** (iptables `-m owner --uid-owner 65532 -j RETURN` at the top of the OUTPUT chain; ip6tables analogue if IPv6 REDIRECT is installed). Otherwise dest-IP Dial of `:80`/`:443` is REDIRECTed back to `:8890` and hairpins. Do not treat Docker `-p 8890:8890` as a substitute.

Ready is `OrigDestBound || OrigDestOff` (D56). When the spec leaves orig-dest disabled, `OrigDestOff` is true so 1.0 processes stay ready. Non-linux `enabled: true` fails `Start` closed and binds nothing.

Residuals (HTTP/3, no Python VM, no TPROXY in the appliance, Linux-only orig-dest, compat subset, live hop/accept vs Reset bind): [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/known-limitations.md).

## Compatibility promise

Standalone **1.0 defaults remain the process defaults**: loopback `127.0.0.1:8888` / `127.0.0.1:8088`, HTTP/1.1 hops, SOCKS peek-close, orig-dest off, no `/compat` until enabled. Lab overlay publishes `:8888` / `:8088`. Host ports when composed: `18888` / `18088`. Soak: `go test ./internal/perf` (CI default N=8; local lab target 100 flows/s for 30s). Lab pin is vendor tag **v1.1.0** + `labmitm:local` (not a GHCR digest). Catalog id is **`labmitm`** (D18).

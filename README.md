# LabMITM

**Laboratory HTTP(S) intercepting proxy** in the LabDNS / LabMail / TacLab family.

Systems under test send HTTP/1.1 absolute-form requests and CONNECT tunnels here. LabMITM will capture every request and response, optionally mint a lab CA and per-host leaves to decrypt TLS, and expose the same authorized operations over native REST `/v1` and MCP `POST /mcp`. Desired state is a fail-closed `labmitm.dev/v1alpha1` YAML file. Captured flows are ephemeral: restart or reset returns the process to the mounted bootstrap and an empty flow store.

LabMITM is a **lab appliance**, not a public edge proxy and not an attack framework. It never wraps, vendors, or execs Python mitmproxy.

[![CI](https://img.shields.io/github/actions/workflow/status/hilather/go-lab-mitmproxy/ci.yml?branch=main&label=CI)](https://github.com/hilather/go-lab-mitmproxy/actions/workflows/ci.yml)
[![Go](https://img.shields.io/github/go-mod/go-version/hilather/go-lab-mitmproxy?label=Go)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/hilather/go-lab-mitmproxy/blob/main/LICENSE)

Status: **HTTP/1.1 forward proxy plus optional TLS intercept, a bounded in-memory flow store, native REST `/v1`, MCP `POST /mcp`, lab static bearer, and a hardened scratch image**. `labmitm serve --config …` binds `spec.listeners.proxy.address` (absolute-form + CONNECT) and captures completed flows. `tls.intercept: true` mints a lab CA and intercepts listed ports (default `{443}`). Management REST/MCP bind only with a usable bearer token (or `--management-listen=off`). Unauthenticated `GET /v1/flows` is 401. REST cookie `labmitm_session` + CSRF. Production UI is UI-001.
Status: **HTTP/1.1 forward proxy plus optional TLS intercept, a bounded in-memory flow store, native REST `/v1`, MCP `POST /mcp`, lab static bearer, and the embedded flow-inspector UI**. `labmitm serve --config …` binds `spec.listeners.proxy.address` (absolute-form + CONNECT) and captures completed flows. `tls.intercept: true` mints a lab CA and intercepts listed ports (default `{443}`). Management REST/MCP bind only with a usable bearer token (or `--management-listen=off`). Unauthenticated `GET /v1/flows` is 401. REST cookie `labmitm_session` + CSRF. The SPA at `/` talks REST only. The container image is a later PR.

Module [`github.com/hilather/go-lab-mitmproxy`](https://github.com/hilather/go-lab-mitmproxy) · Binary `labmitm` · Image `ghcr.io/hilather/labmitm` · YAML `apiVersion: labmitm.dev/v1alpha1`, `kind: LabMITM`

New here? Start with [START-HERE.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/START-HERE.md). Architecture, ADRs, and the program board are indexed in [Documentation](#documentation).

This repository will become the first-party HTTP(S) intercept appliance for [mcp-integration-lab](https://github.com/hilather/mcp-integration-lab). There is no off-the-shelf mitmproxy service in that lab today. Family siblings:

- [LabDNS](https://github.com/hilather/go-lab-dns)
- [LabMail](https://github.com/hilather/go-lab-maildev)
- [LabLDAP](https://github.com/hilather/go-lab-ldap-mcp)
- [TacLab](https://github.com/hilather/go-lab-tacacs-mcp)

## Intended lab role

Standalone defaults bind loopback (an intercepting proxy is an open-proxy loaded gun). The later lab overlay publishes container ports.

| Plane | Standalone default | Lab / compose (later) | Role |
|---|---|---|---|
| HTTP/1.1 forward proxy | `127.0.0.1:8888` | `:8888` (host `18888`) | absolute-form + CONNECT |
| Management / UI / REST / MCP | `127.0.0.1:8088` | `:8088` (host `18088`) | inspect captured flows |
| Metrics | `127.0.0.1:9090` | loopback-per-container | hand-rolled OpenMetrics |

The labinfo catalog id will be **`labmitm`** (no legacy id to preserve). Compose-in to mcp-integration-lab is a follow-on lab PR after this repo’s SWAP-001 overlays land.

## Quick start

```bash
git clone https://github.com/hilather/go-lab-mitmproxy.git
cd go-lab-mitmproxy
go version   # go1.26.x
go build -o bin/labmitm ./cmd/labmitm
./bin/labmitm version
./bin/labmitm validate --config testdata/config/valid/defaults.yaml
./bin/labmitm canonicalize --config testdata/config/valid/defaults.yaml --format json
./bin/labmitm serve --config testdata/config/valid/defaults.yaml --proxy-listen 127.0.0.1:8888 --management-listen=off
```

`serve --management-listen=off` binds the proxy only. Binding management requires `spec.management.auth.mode: bearer` with ≥1 token file (allow-all is not a 1.0 posture). Empty `spec: {}` materializes loopback defaults `127.0.0.1:8888` / `127.0.0.1:8088`. `tls.intercept: true` mints a lab CA and intercepts CONNECT on listed ports (default `443`); handshake failure does not fall back to a blind tunnel. The CA certificate is `GET /v1/ca` (PEM cert only, authenticated; never the key; not on `:8888`). There is no `serve --token-file`.

Hardened image: non-root UID `65532`, scratch, read-only root, `cap_drop: ALL`, system CA bundle copied so `x509.SystemCertPool()` is non-empty. Healthcheck is HTTP ready (exec form). Compose smoke: [examples/compose.smoke.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/compose.smoke.yaml).
`serve --management-listen=off` binds the proxy only. Binding management requires `spec.management.auth.mode: bearer` with ≥1 token file (allow-all is not a 1.0 posture). Empty `spec: {}` materializes loopback defaults `127.0.0.1:8888` / `127.0.0.1:8088`. `tls.intercept: true` mints a lab CA and intercepts CONNECT on listed ports (default `443`); handshake failure does not fall back to a blind tunnel. The CA certificate is `GET /v1/ca` (PEM cert only, authenticated; never the key; not on `:8888`). Production UI assets: `make web-build` (Node **22.14.0**) copies `web/dist` into `internal/web/dist`. `spec.ui.enabled: false` 404s `/` and keeps REST/MCP.

## Build and test

```bash
make format
make lint
make generate
make verify-generated
make test
make test-config-compat
make test-docs
make test-parity
make test-container
make build
```

Required CI jobs: format, lint, unit, documentation, config-compat, generated-file, parity, container-test. There is no optional or bypassable job. `make test-container` needs Docker.
make web-test
make web-build
make build
```

Required CI jobs: format, lint, unit, documentation, config-compat, generated-file, parity, web. There is no optional or bypassable job.

## Documentation

The numbered pack is normative after FND-001. Cross-file links are absolute.

| Path | Topic |
|---|---|
| [START-HERE.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/START-HERE.md) | Onboarding |
| [AGENTS.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/AGENTS.md) | Contributor / agent rules |
| [docs/README.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/README.md) | Pack index |
| [docs/01-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/01-architecture.md) | Process and package model |
| [docs/02-proxy-semantics.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md) | Absolute-form, CONNECT, admission, target guards |
| [docs/03-tls-interception.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/03-tls-interception.md) | Lab CA, leaves, ALPN, upstream verify |
| [docs/04-flow-store.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/04-flow-store.md) | Caps, epoch, truncate, spill |
| [docs/05-rules.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/05-rules.md) | Deterministic rules, breakpoint, replay |
| [docs/06-state-and-configuration.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/06-state-and-configuration.md) | YAML, revisions, reset |
| [docs/07-control-plane-and-parity.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/07-control-plane-and-parity.md) | Capability registry |
| [docs/08-rest-api.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/08-rest-api.md) | Native `/v1` |
| [docs/09-mcp-api.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/09-mcp-api.md) | MCP tools and resources |
| [docs/10-security-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/10-security-architecture.md) | Threat model, CA, Dial isolation |
| [docs/11-observability.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/11-observability.md) | Logs, metrics, probes |
| [docs/12-testing-strategy.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/12-testing-strategy.md) | Test layers |
| [docs/13-deployment.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/13-deployment.md) | Image, compose, CLI |
| [docs/14-integration-lab.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/14-integration-lab.md) | Overlay BOM for mcp-integration-lab |
| [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/known-limitations.md) | 1.0 residuals |
| [tasks/00-program-board.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/tasks/00-program-board.md) | PRs 1–14 |
| [CHANGELOG.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/CHANGELOG.md) | Curated history |

## License

[Apache License 2.0](https://github.com/hilather/go-lab-mitmproxy/blob/main/LICENSE)

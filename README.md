# LabMITM

**Intercepting HTTP(S) lab appliance** in the LabDNS / LabLDAP / TacLab / LabMail family.

LabMITM is an independent Go rewrite of [mitmproxy](https://github.com/mitmproxy/mitmproxy) for [mcp-integration-lab](https://github.com/hilather/mcp-integration-lab). Systems under test send HTTP, HTTPS, and WebSockets through it. LabMITM intercepts TLS with a mounted lab CA, records flows, and exposes **every public control on both REST and MCP**. Captured flows are ephemeral. Desired state is fail-closed YAML.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/hilather/go-lab-mitmproxy/blob/main/LICENSE)

Status: **design pack**. Implementation has not started. Agents execute [docs/tasks/00-program-board.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/tasks/00-program-board.md). Residuals: [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/known-limitations.md).

Module [`github.com/hilather/go-lab-mitmproxy`](https://github.com/hilather/go-lab-mitmproxy) · Binary `labmitm` · Image `ghcr.io/hilather/labmitm` · YAML `apiVersion: labmitm.dev/v1alpha1`, `kind: LabMITM`

New here? Start with [START-HERE.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/START-HERE.md). Architecture, ADRs, and the program board are indexed below.

Family siblings:

- [LabDNS](https://github.com/hilather/go-lab-dns)
- [LabLDAP](https://github.com/hilather/go-lab-ldap-mcp)
- [TacLab](https://github.com/hilather/go-lab-tacacs-mcp)
- [LabMail](https://github.com/hilather/go-lab-maildev)
- [MCP Integration Lab](https://github.com/hilather/mcp-integration-lab)

## Intended lab role

| Plane | Default host port | Container | Role |
|---|---|---|---|
| HTTP(S) proxy | 18880 | 8080 | systems under test (`HTTP_PROXY` / CONNECT) |
| Management / UI / REST / MCP | 18081 | 8081 | native `/v1`, `POST /mcp`, mitmweb compat, SPA |
| SOCKS5 (optional) | 11080 | 10800 | SOCKS CONNECT |

Those listeners, ephemeral flows, Git-mounted YAML, and bearer auth are the add contract for mcp-integration-lab (labinfo id **`labmitm`**).

## Quick start (after FND-001)

```bash
git clone https://github.com/hilather/go-lab-mitmproxy.git
cd go-lab-mitmproxy
go version   # go1.26.x
go build -o bin/labmitm ./cmd/labmitm
./bin/labmitm version
./bin/labmitm help
./bin/labmitm validate --config testdata/config/valid/defaults.yaml
./bin/labmitm ca generate --out /tmp/labmitm-ca
./bin/labmitm serve --config testdata/config/valid/defaults.yaml \
  --proxy-listen 127.0.0.1:8080 --management-listen 127.0.0.1:8081
```

Until FND-001 lands, use the design pack only.

`serve` binds the proxy from YAML (override `--proxy-listen`) and management HTTP from `spec.listeners.management.address` (override `--management-listen ADDR|off`). Native `/v1`, SPA at `/`, Streamable HTTP `POST /mcp`, and mitmweb compat (when `compatEnabled`) share the management listener. Ready requires the proxy bound **and** the CA loaded. Probe with `labmitm healthcheck --url=http://127.0.0.1:8081/v1/health/ready`.

Hardened image (DEP-001): non-root UID `65532`, scratch, read-only root, `cap_drop: ALL`. Transparent / TUN / WireGuard / local-capture are **not** in that image ([ADR 0009](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0009-privileged-modes-deferred.md)).

## Build and test (after FND-001)

```bash
make format
make lint
make generate
make verify-generated
make test
make test-race
make test-fuzz-smoke
make test-integration
make test-parity
make test-config-compat
make test-docs
make test-container
make test-changelog
make web-test
make web-build
make build
```

Required CI jobs grow with the program board and are never optional. A `v*` tag is refused unless Release `tag-gate` sees those jobs green on the exact SHA. If CI fails, fix it and harden it; do not merge red PRs or red PR chains.

## REST and MCP parity

Every public REST control has an MCP twin except transport-only rows (`REST_ONLY_PROTOCOL`). Agents must keep [docs/05-control-plane-and-parity.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/05-control-plane-and-parity.md) and `make test-parity` in lockstep. Tool names `mitm_*` are frozen. Protocol pin: MCP `2026-07-28` with `allowLegacyClients` for MCPJungle ([ADR 0006](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0006-pin-mcp-protocol-versions.md)).

## Implementation waves

Parallel lanes are defined in [docs/tasks/parallelization-plan.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/tasks/parallelization-plan.md):

0. Foundation  
1. YAML schema  
2. HTTP/1 proxy ∥ filters ∥ flow store  
3. TLS intercept ∥ observability  
4. HTTP/2 ∥ WebSocket ∥ extra modes ∥ built-in addons  
5. Application snapshot → replay  
6. REST → MCP ∥ mitmweb compat  
7. Auth ∥ Starlark ∥ container  
8. UI ∥ lab overlay ∥ GA  
9. HTTP/3 and privileged modes (1.1, not 1.0 GA)

## Documentation

The numbered pack is normative. Cross-file links are absolute.

| Path | Topic |
|---|---|
| [START-HERE.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/START-HERE.md) | Onboarding |
| [AGENTS.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/AGENTS.md) | Contributor / agent rules (integration tests, parity, green CI) |
| [docs/README.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/README.md) | Pack index |
| [docs/01-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/01-architecture.md) | Process and package model |
| [docs/02-proxy-semantics.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md) | Modes, HTTP/1, CONNECT, H2, WS |
| [docs/03-flow-store.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/03-flow-store.md) | Caps, intercept, replay, HAR |
| [docs/04-state-and-configuration.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/04-state-and-configuration.md) | YAML, revisions, reset |
| [docs/05-control-plane-and-parity.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/05-control-plane-and-parity.md) | Capability registry |
| [docs/06-rest-api.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/06-rest-api.md) | Native `/v1` |
| [docs/07-mcp-api.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/07-mcp-api.md) | MCP tools and resources |
| [docs/08-security-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/08-security-architecture.md) | Auth, CA, smuggling |
| [docs/10-testing-strategy.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/10-testing-strategy.md) | Test layers |
| [docs/13-integration-lab-add.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/13-integration-lab-add.md) | mcp-integration-lab BOM |
| [docs/implementation-design.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/implementation-design.md) | Import DAG and PR mapping |
| [docs/tasks/00-program-board.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/tasks/00-program-board.md) | Work packages FND-001–GA-001 |
| [CHANGELOG.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/CHANGELOG.md) | Curated history |

## License

[Apache License 2.0](https://github.com/hilather/go-lab-mitmproxy/blob/main/LICENSE). Independent rewrite; not a derivative of mitmproxy source ([ADR 0010](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0010-independent-rewrite.md)).

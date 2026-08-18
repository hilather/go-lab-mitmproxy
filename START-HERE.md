# Start here

LabMITM is a Go intercepting-proxy lab appliance in the LabDNS / LabLDAP / TacLab / LabMail family. It is an independent rewrite of [mitmproxy](https://github.com/mitmproxy/mitmproxy) for [mcp-integration-lab](https://github.com/hilather/mcp-integration-lab): HTTP/1 and HTTP/2 (HTTP/3 in 1.1), WebSockets, TLS interception, flow capture, intercept/resume/replay, REST, MCP, and an embedded operator UI.

This repository currently holds the **normative design pack**. Implementation starts at [docs/tasks/00-program-board.md](docs/tasks/00-program-board.md) with FND-001.

If you want to understand the product, stay on this page, then read the [README](README.md). If you want to change it, read [AGENTS.md](AGENTS.md) before touching anything.

## Five-minute path (after FND-001)

1. Install **Go 1.26** and clone this repository.
2. `go build -o bin/labmitm ./cmd/labmitm`
3. `./bin/labmitm version`
4. `./bin/labmitm help`
5. `./bin/labmitm validate --config testdata/config/valid/defaults.yaml`
6. `./bin/labmitm serve --config testdata/config/valid/defaults.yaml --proxy-listen 127.0.0.1:8080 --management-listen 127.0.0.1:8081`

Until FND-001 lands, those binaries do not exist. The pack is still the source of truth.

Point a client at the proxy (`HTTP_PROXY=http://127.0.0.1:8080` plus the lab CA) and drive capture from REST `/v1`, `POST /mcp`, or the UI at `/`. mitmweb-compatible routes are a compat adapter, not the native contract.

## What to read next

| If you are… | Read |
|---|---|
| Running a lab (later) | [README.md](README.md), [docs/11-deployment.md](docs/11-deployment.md), [docs/13-integration-lab-add.md](docs/13-integration-lab-add.md) |
| Writing YAML | [docs/04-state-and-configuration.md](docs/04-state-and-configuration.md) |
| Implementing the proxy | [docs/02-proxy-semantics.md](docs/02-proxy-semantics.md), [docs/23-tls-and-certificates.md](docs/23-tls-and-certificates.md), [docs/adr/0002-in-tree-proxy-core.md](docs/adr/0002-in-tree-proxy-core.md) |
| Wiring an agent | [docs/05-control-plane-and-parity.md](docs/05-control-plane-and-parity.md), [docs/07-mcp-api.md](docs/07-mcp-api.md) |
| Keeping mitmweb clients green | [docs/12-mitmweb-compat.md](docs/12-mitmweb-compat.md) |
| Taking a work package | [docs/tasks/00-program-board.md](docs/tasks/00-program-board.md), [docs/tasks/parallelization-plan.md](docs/tasks/parallelization-plan.md) |
| Changing behavior | [AGENTS.md](AGENTS.md), then the normative doc for that area |

The full catalog is [docs/README.md](docs/README.md).

## For contributors and agents

Before changing code or expanding the pack:

1. Read [AGENTS.md](AGENTS.md) completely.
2. Read architecture, proxy semantics, flow store, state, control-plane parity, security, and testing.
3. Read every ADR that affects the task (`docs/adr/`).
4. Take one work package from [docs/tasks/00-program-board.md](docs/tasks/00-program-board.md) whose dependencies are complete.
5. Add or update **unit, integration, and (when REST/MCP change) parity** tests before declaring the task done.
6. Update every affected document in the same change.
7. Run every required local verification target. **CI must be green** before the PR is ready and at the end of a PR chain. If CI fails, fix and harden it.

Do not implement REST, MCP, proxy, TLS, configuration, or the store from a task summary when a normative design document exists.

### Definition of done

A task is not done until:

- The implementation is complete and reviewable.
- Unit and regression tests cover all changed behavior.
- **Integration tests** cover new protocol, API, MCP, and mode behavior.
- Configuration changes have positive and negative validation tests.
- REST and MCP parity checks pass (`make test-parity`) whenever either adapter or the registry changes.
- Race, fuzz, lint, generation, documentation, and relevant end-to-end checks pass.
- All affected documentation is current.
- No CI check is ignored, bypassed, or marked optional to get a merge.
- User-visible changes are recorded in [CHANGELOG.md](CHANGELOG.md).

GA / 1.0 is not done without the embedded operator UI (UI-001). LabMITM is a laboratory intercepting proxy, not a production edge proxy. Residuals: [docs/known-limitations.md](docs/known-limitations.md).

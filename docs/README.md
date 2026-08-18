# Documentation

Operator front door: [README.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/README.md). Onboarding: [START-HERE.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/START-HERE.md). Agent rules: [AGENTS.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/AGENTS.md).

This page is the catalog. Normative design documents win over task summaries. After FND-001 the numbered pack is the source of truth.

## Root

| Path | Role |
|---|---|
| [README.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/README.md) | Product page |
| [START-HERE.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/START-HERE.md) | Onboarding and definition of done |
| [AGENTS.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/AGENTS.md) | Mandatory contributor / agent instructions |
| [CONTRIBUTING.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/CONTRIBUTING.md) | PR workflow |
| [SECURITY.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/SECURITY.md) | Vulnerability reporting |
| [CHANGELOG.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/CHANGELOG.md) | Curated history |
| [MANIFEST.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/MANIFEST.md) | Pack inventory |
| [LICENSE](https://github.com/hilather/go-lab-mitmproxy/blob/main/LICENSE) | Apache-2.0 |
| [RELEASE-NOTES-TEMPLATE.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/RELEASE-NOTES-TEMPLATE.md) | Between-tag notes template |
| [CI-FAILURE-HARDENING-TEMPLATE.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/CI-FAILURE-HARDENING-TEMPLATE.md) | CI hardening record |

## Architecture

| Path | Topic |
|---|---|
| [01-architecture.md](01-architecture.md) | Process, package model, closed decisions |
| [02-proxy-semantics.md](02-proxy-semantics.md) | Modes, HTTP/1, CONNECT, HTTP/2, WebSocket |
| [03-flow-store.md](03-flow-store.md) | Caps, intercept, replay, dump, HAR |
| [04-state-and-configuration.md](04-state-and-configuration.md) | YAML, revisions, reset |
| [05-control-plane-and-parity.md](05-control-plane-and-parity.md) | Shared capability registry |
| [implementation-design.md](implementation-design.md) | Package tree, import DAG, PR mapping |
| [22-addon-pipeline.md](22-addon-pipeline.md) | Go addons, Starlark, built-in transforms |
| [23-tls-and-certificates.md](23-tls-and-certificates.md) | CA, leaf minting, mTLS, onboarding |
| [24-filter-language.md](24-filter-language.md) | mitmproxy-compatible filters (RE2) |

## Interfaces

| Path | Topic |
|---|---|
| [06-rest-api.md](06-rest-api.md) | Native REST `/v1` |
| [07-mcp-api.md](07-mcp-api.md) | MCP tools, resources, protocol pin |
| [09-observability.md](09-observability.md) | Metrics, logs, health |
| [12-mitmweb-compat.md](12-mitmweb-compat.md) | mitmweb REST shim |
| [17-error-model.md](17-error-model.md) | Domain errors |

## Security, operations, release

| Path | Topic |
|---|---|
| [08-security-architecture.md](08-security-architecture.md) | Authn/z, smuggling, CA |
| [20-threat-model.md](20-threat-model.md) | Threat model |
| [10-testing-strategy.md](10-testing-strategy.md) | Test layers, always-on integration tests |
| [11-deployment.md](11-deployment.md) | Container and process |
| [13-integration-lab-add.md](13-integration-lab-add.md) | mcp-integration-lab BOM |
| [14-release-engineering.md](14-release-engineering.md) | Tags, tag-gate, green CI |
| [15-documentation-governance.md](15-documentation-governance.md) | Docs policy |
| [16-compatibility-and-versioning.md](16-compatibility-and-versioning.md) | Compatibility |
| [18-roadmap-and-non-goals.md](18-roadmap-and-non-goals.md) | Waves and deferred work |
| [19-acceptance-criteria.md](19-acceptance-criteria.md) | GA acceptance |
| [21-standards-and-references.md](21-standards-and-references.md) | RFCs and mitmproxy docs |
| [known-limitations.md](known-limitations.md) | 1.0 residuals |

## Architecture decisions

| ADR | Decision |
|---|---|
| [0001](adr/0001-use-go.md) | Use Go |
| [0002](adr/0002-in-tree-proxy-core.md) | In-tree proxy core; no Python wrap |
| [0003](adr/0003-ephemeral-flows-and-gitops.md) | Ephemeral flows and GitOps |
| [0004](adr/0004-shared-capability-registry.md) | Shared capability registry |
| [0005](adr/0005-lab-static-bearer.md) | Lab static bearer |
| [0006](adr/0006-pin-mcp-protocol-versions.md) | Pin MCP protocol versions |
| [0007](adr/0007-starlark-not-cpython.md) | Starlark scripts, not CPython |
| [0008](adr/0008-mitmweb-compat-surface.md) | mitmweb compat adapter |
| [0009](adr/0009-privileged-modes-deferred.md) | Privileged modes are 1.1 |
| [0010](adr/0010-independent-rewrite.md) | Independent rewrite, Apache-2.0 |
| [0011](adr/0011-http2-now-http3-later.md) | HTTP/2 in 1.0; HTTP/3 in 1.1 |
| [0012](adr/0012-ca-is-secret-not-runtime.md) | CA is a mounted secret |

## Task lists

See [tasks/README.md](tasks/README.md) and the [program board](tasks/00-program-board.md).

| Path | Package |
|---|---|
| [00-program-board.md](tasks/00-program-board.md) | Milestones, waves, status |
| [parallelization-plan.md](tasks/parallelization-plan.md) | Parallel lanes |
| [reviewer-checklist.md](tasks/reviewer-checklist.md) | Review bar |
| [agent-task-template.md](tasks/agent-task-template.md) | Task file template |
| [01-repository-foundation.md](tasks/01-repository-foundation.md) | FND-001 |
| [02-domain-and-configuration.md](tasks/02-domain-and-configuration.md) | CFG-001 |
| [03-proxy-core-http1.md](tasks/03-proxy-core-http1.md) | PROXY-001 |
| [04-tls-interception.md](tasks/04-tls-interception.md) | TLS-001 |
| [05-http2.md](tasks/05-http2.md) | H2-001 |
| [06-websocket.md](tasks/06-websocket.md) | WS-001 |
| [07-flow-store.md](tasks/07-flow-store.md) | STORE-001 |
| [08-filters-and-intercept.md](tasks/08-filters-and-intercept.md) | FILT-001 |
| [09-transforms-addons.md](tasks/09-transforms-addons.md) | ADDON-001 |
| [10-replay-export.md](tasks/10-replay-export.md) | REPLAY-001 |
| [11-snapshot-state.md](tasks/11-snapshot-state.md) | STA-001 |
| [12-rest-control-plane.md](tasks/12-rest-control-plane.md) | API-001 |
| [13-mcp-control-plane.md](tasks/13-mcp-control-plane.md) | MCP-001 |
| [14-mitmweb-compat.md](tasks/14-mitmweb-compat.md) | COMPAT-001 |
| [15-auth-security.md](tasks/15-auth-security.md) | SEC-001 |
| [16-observability.md](tasks/16-observability.md) | OBS-001 |
| [17-cli-and-container.md](tasks/17-cli-and-container.md) | DEP-001 |
| [18-starlark-scripts.md](tasks/18-starlark-scripts.md) | SCRIPT-001 |
| [19-modes-socks-reverse-upstream.md](tasks/19-modes-socks-reverse-upstream.md) | MODE-001 |
| [20-embedded-ui.md](tasks/20-embedded-ui.md) | UI-001 |
| [21-integration-lab.md](tasks/21-integration-lab.md) | LAB-001 |
| [22-ci-docs-release.md](tasks/22-ci-docs-release.md) | REL-001 |
| [23-http3-quic.md](tasks/23-http3-quic.md) | H3-001 |
| [24-privileged-modes.md](tasks/24-privileged-modes.md) | PRIV-001 |
| [25-ga-hardening.md](tasks/25-ga-hardening.md) | GA-001 |

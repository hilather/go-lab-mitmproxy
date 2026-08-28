# Documentation

Operator front door: [README.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/README.md)
(product page, YAML bootstrap, REST/MCP state-loading APIs). Onboarding:
[START-HERE.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/START-HERE.md).
Agent rules: [AGENTS.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/AGENTS.md).

This page is the catalog. Normative design documents win over task summaries.
The numbered pack is the source of truth.

## Root

| Path | Role |
|---|---|
| [README.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/README.md) | Product page |
| [START-HERE.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/START-HERE.md) | Onboarding and definition of done |
| [AGENTS.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/AGENTS.md) | Mandatory contributor / agent instructions |
| [CHANGELOG.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/CHANGELOG.md) | Curated history |
| [LICENSE](https://github.com/hilather/go-lab-mitmproxy/blob/main/LICENSE) | Apache-2.0 |

## Architecture

| Path | Topic |
|---|---|
| [01-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/01-architecture.md) | Process and package model |
| [02-proxy-semantics.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md) | Absolute-form, CONNECT, admission, target guards |
| [03-tls-interception.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/03-tls-interception.md) | Lab CA, leaves, ALPN, upstream verify |
| [04-flow-store.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/04-flow-store.md) | Caps, wait, wipe, spill |
| [05-rules.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/05-rules.md) | Deterministic rules, breakpoint, replay |
| [06-state-and-configuration.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/06-state-and-configuration.md) | YAML, revisions, reset |
| [07-control-plane-and-parity.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/07-control-plane-and-parity.md) | Shared capability registry |

## Interfaces

| Path | Topic |
|---|---|
| [08-rest-api.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/08-rest-api.md) | REST `/v1` |
| [09-mcp-api.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/09-mcp-api.md) | MCP tools and protocol pin |
| [11-observability.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/11-observability.md) | Metrics, logs, health |

## Security, operations, release

| Path | Topic |
|---|---|
| [10-security-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/10-security-architecture.md) | Authn/z, CA, Dial isolation |
| [12-testing-strategy.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/12-testing-strategy.md) | Test layers |
| [13-deployment.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/13-deployment.md) | Container and process |
| [14-integration-lab.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/14-integration-lab.md) | Overlay BOM for mcp-integration-lab |
| [known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/known-limitations.md) | 1.0 defaults + 1.2 residuals |
| [releases/v1.3.0.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/releases/v1.3.0.md) | 1.3.0 tag notes (live hop/protocol feature gates D51') |
| [releases/v1.2.0.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/releases/v1.2.0.md) | 1.2.0 tag notes (protocol expansion D58–D68) |
| [releases/v1.1.1.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/releases/v1.1.1.md) | 1.1.1 tag notes (overlay/docs/D18 closeout) |
| [releases/v1.1.0.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/releases/v1.1.0.md) | 1.1.0 tag notes (first Git tag) |
| [releases/v1.0.0-rc.1.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/releases/v1.0.0-rc.1.md) | Untagged 1.0 candidate notes |

## Architecture decisions

| ADR | Decision |
|---|---|
| [0001](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0001-use-go.md) | Use Go |
| [0002](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0002-in-tree-http-forward-proxy.md) | In-tree HTTP/1.1 forward proxy (D7, D8, D16, D19–D21) |
| [0003](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0003-ephemeral-flows-and-gitops.md) | Ephemeral flows and GitOps (D3) |
| [0004](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0004-shared-capability-registry.md) | Shared capability registry (D4) |
| [0005](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0005-lab-static-bearer.md) | Lab static bearer (D6) |
| [0006](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0006-pin-mcp-protocol-versions.md) | Pin MCP protocol versions (D14, D15) |
| [0007](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0007-no-mitmproxy-compat-surface.md) | No mitmproxy compat surface (D5) |
| [0008](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0008-additive-v1alpha1-11.md) | Additive v1alpha1 1.1 fields (D22, D25, D41, D51) |
| [0009](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0009-http2-via-http2x.md) | HTTP/2 via http2x; D8 scope only (D7 stands) |
| [0010](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0010-socks-and-original-destination.md) | SOCKS5 multiplex + orig-dest REDIRECT; TPROXY stays rejected |
| [0011](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0011-optional-compat-flow-rest.md) | Optional compat flow REST; `/v1`+MCP primacy stands |
| [0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) | 1.2 protocol expansion (D58–D68); D7 stands |
| [0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md) | Live protocol feature gates (D51', D22 carve); 1.2 flags stay Reset-only |

## Plans

| Path | Topic |
|---|---|
| [qa-websocket-frame-rules.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/tasks/plans/qa-websocket-frame-rules.md) | #52 post-101 WebSocket frame rules (plan only; skeptic **ACCEPT**) |

## Task lists

| Path | Package |
|---|---|
| [00-program-board.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/tasks/00-program-board.md) | PRs 1–14 and milestones |
| [README.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/tasks/README.md) | Task working rules |

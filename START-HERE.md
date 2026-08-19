# Start here

LabMITM is a laboratory HTTP(S) intercepting proxy in the LabDNS / LabMail / TacLab family. Systems under test send HTTP/1.1 absolute-form requests and CONNECT tunnels to it. LabMITM will capture, optionally intercept TLS with a lab CA, and (once implemented) expose every flow over REST, MCP, and an embedded flow-inspector UI. It never wraps Python mitmproxy.

If you want to run what exists today, stay on this page, then follow the [README](README.md). If you want to change it, read [AGENTS.md](AGENTS.md) before touching code.

## Five-minute path (foundation stub)

1. Install **Go 1.26** and clone this repository.
2. `go build -o bin/labmitm ./cmd/labmitm`
3. `./bin/labmitm version`
4. `./bin/labmitm help`

There is **no proxy listener** in this foundation slice. `serve`, `validate`, `canonicalize`, `healthcheck`, and `mcp-stdio` are planned commands and currently exit 2.

YAML field rules, revisions, and reset live in [docs/06-state-and-configuration.md](docs/06-state-and-configuration.md). Proxy accept/reject tables live in [docs/02-proxy-semantics.md](docs/02-proxy-semantics.md). REST and MCP twins are in [docs/08-rest-api.md](docs/08-rest-api.md) and [docs/09-mcp-api.md](docs/09-mcp-api.md).

## What to read next

| If you are… | Read |
|---|---|
| Running a lab (later) | [README.md](README.md), [docs/13-deployment.md](docs/13-deployment.md), [docs/14-integration-lab.md](docs/14-integration-lab.md) |
| Writing YAML | [docs/06-state-and-configuration.md](docs/06-state-and-configuration.md) |
| Implementing the proxy | [docs/02-proxy-semantics.md](docs/02-proxy-semantics.md), [docs/adr/0002-in-tree-http-forward-proxy.md](docs/adr/0002-in-tree-http-forward-proxy.md) |
| Implementing TLS intercept | [docs/03-tls-interception.md](docs/03-tls-interception.md) |
| Wiring an agent | [docs/07-control-plane-and-parity.md](docs/07-control-plane-and-parity.md), [docs/09-mcp-api.md](docs/09-mcp-api.md) |
| Changing behavior | [AGENTS.md](AGENTS.md), then the normative doc for that area |

The full catalog — architecture, ADRs, task lists — is in [docs/README.md](docs/README.md) and linked from the [README documentation map](README.md#documentation).

## For contributors and agents

Before changing code:

1. Read [AGENTS.md](AGENTS.md) completely.
2. Read architecture, proxy semantics, TLS, store, rules, state, control-plane parity, security, and testing: [docs/01-architecture.md](docs/01-architecture.md), [docs/02-proxy-semantics.md](docs/02-proxy-semantics.md), [docs/03-tls-interception.md](docs/03-tls-interception.md), [docs/04-flow-store.md](docs/04-flow-store.md), [docs/05-rules.md](docs/05-rules.md), [docs/06-state-and-configuration.md](docs/06-state-and-configuration.md), [docs/07-control-plane-and-parity.md](docs/07-control-plane-and-parity.md), [docs/10-security-architecture.md](docs/10-security-architecture.md), [docs/12-testing-strategy.md](docs/12-testing-strategy.md).
3. Read every ADR that affects the task (`docs/adr/`).
4. Take one work package from [tasks/00-program-board.md](tasks/00-program-board.md) whose dependencies are complete.
5. Add or update tests before declaring the task done.
6. Update every affected document in the same change.
7. Run every required local verification target (`make test`, `make test-docs`, and the rest listed in [AGENTS.md](AGENTS.md)).

Do not implement REST, MCP, proxy, TLS, configuration, or the store from a task summary when a normative design document exists. The numbered pack is the source of truth. If an invariant must change, write an ADR and update the normative documentation first.

Coordinators allocate work with [tasks/00-program-board.md](tasks/00-program-board.md). Parallel work is safe only when package ownership and schema ownership do not overlap. Integration changes to shared domain types, generated schemas, or the capability registry must be serialized.

### Definition of done

A task is not done until:

- The implementation is complete and reviewable.
- Unit and regression tests cover all changed behavior.
- Protocol changes have integration and compatibility tests.
- Configuration changes have positive and negative validation tests.
- REST and MCP parity checks pass (once those targets exist).
- Race, fuzz, lint, generation, documentation, and relevant end-to-end checks pass.
- All affected documentation is current.
- No CI check is ignored, bypassed, or marked optional to get a merge.
- User-visible and operator-visible changes are recorded in [CHANGELOG.md](CHANGELOG.md).

GA / 1.0 is not done without the embedded flow-inspector UI (PR 13). LabMITM is a lab intercepting proxy, not a public MITM product and not an attack tool. Residuals: [docs/known-limitations.md](docs/known-limitations.md).

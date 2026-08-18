# Repository Instructions for Agents

These instructions apply to every human or AI agent working in this repository. More specific `AGENTS.md` files may add stricter rules but may not weaken this file.

This repository is the **LabMITM** design pack and (after FND-001) the implementation of a Go rewrite of [mitmproxy](https://github.com/mitmproxy/mitmproxy) for [mcp-integration-lab](https://github.com/hilather/mcp-integration-lab). It is an independent rewrite. Do not copy mitmproxy Python source, web assets, or dump codecs. Implement from the numbered pack, public documentation, and interoperability fixtures.

## Required reading

Before modifying code, read:

1. `docs/01-architecture.md`
2. `docs/02-proxy-semantics.md`
3. `docs/03-flow-store.md`
4. `docs/04-state-and-configuration.md`
5. `docs/05-control-plane-and-parity.md`
6. `docs/08-security-architecture.md`
7. `docs/10-testing-strategy.md`
8. `docs/22-addon-pipeline.md`
9. `docs/23-tls-and-certificates.md`
10. Every ADR relevant to the area being changed

The numbered pack under `docs/` is the source of truth after FND-001. Do not invent paths, types, filter operators, validate rules, capability IDs, MCP tool names, or REST paths. If an invariant must change, write an ADR first and update the normative document in the same change.

## Architectural rules

- REST and MCP are adapters. Domain behavior belongs in `internal/app`, `internal/proxy`, `internal/tlsint`, `internal/store`, `internal/filter`, `internal/addon`, `internal/config`, or `internal/model`.
- REST handlers, MCP handlers, and the mitmweb compat adapter must never implement independent business logic and must never call each other.
- Every public capability must be represented in the central capability registry (`internal/capabilities`).
- The proxy data plane must keep accepting if REST/MCP is slow or unbound. `internal/proxy` must not import `internal/control`, `internal/web`, or `net/http` servers for the management plane.
- Desired state is YAML. Captured flows are not. Reset rereads bootstrap **and** wipes the flow store (the lab CA mount is a secret, not wiped).
- The service must not write to the bootstrap configuration file.
- Do not add a database, flow-directory persistence, hidden volume, or other durability mechanism without an approved ADR.
- Do not wrap, exec, or vendor the Python mitmproxy process.
- Do not embed CPython. 1.0 scripting is Starlark plus in-tree Go addons (ADR 0007).
- Do not add transparent, TUN, WireGuard, or local-capture modes to the default `cap_drop: ALL` image (ADR 0009).
- Hide third-party HTTP/2, MCP, YAML, and Starlark types behind internal adapters.
- `block_global` defaults **false** in the lab overlay. mitmproxy’s default `true` would refuse published-lab clients.

## Tests and regressions

- **Every area must have regression tests.** Every code path, protocol behavior, API capability, configuration semantic, operational script, and bug fix must have appropriate automated regression coverage.
- **Always add integration tests** for new proxy behavior, new REST capabilities, new MCP tools, new modes, new addons/transforms, and new TLS behavior. Unit tests alone are not enough for a protocol appliance.
- A bug fix must begin with or include a test that fails before the fix and passes after it.
- New proxy behavior requires session transcripts over `internal/proxytest` (HTTP/1, CONNECT, HTTP/2, WebSocket as applicable).
- New REST functionality requires contract tests **and** an integration test that drives the listener.
- New MCP functionality requires protocol tests **and** REST/MCP parity tests.
- Configuration changes require valid, invalid, reserved-key, normalization, and revision tests.
- Never delete or weaken a test merely to make CI pass unless the test is provably incorrect; document the reason in the change.

## REST and MCP parity

- **Every public REST control capability must have an MCP equivalent** except rows marked `REST_ONLY_PROTOCOL`.
- Every state-changing MCP tool must have a REST equivalent.
- Parameterized MCP read tools must have REST equivalents; MCP resources may mirror REST GET representations.
- Both adapters must use the same input and output domain types and the same authorization decision.
- Every mutation must support validation, dry-run planning, optimistic concurrency, idempotency, actor identity, reason, deterministic errors, audit emission, and an atomic commit.
- Run `make test-parity` whenever REST, MCP, schemas, authorization, or application commands change.
- The mitmweb compat adapter is `REST_ONLY_PROTOCOL`. Each compat route must still call `app.Service` and must have a native `/v1` + MCP twin.

## CI is mandatory

- All required CI checks must pass before merge, before pushing a pull request that is ready for review, at the **end of a PR chain**, and before a release tag is created.
- Do not bypass, skip, mark optional, or administratively override a failing check to ship a change.
- Treat every CI failure as either a product defect or a pipeline defect.
- When CI fails, **fix the immediate cause and harden** so the same failure is easier to diagnose and less likely to recur (regression test, better assertions, deterministic fixtures, timeouts, diagnostics, pinning, hermetic setup). File a record under `docs/ci-failure-hardening/` using `CI-FAILURE-HARDENING-TEMPLATE.md`.
- Do not hide flaky tests with broad retries. Find and remove the source of nondeterminism.
- A task is incomplete until all relevant local and CI-equivalent targets pass.
- Placeholders must fail closed, not succeed as no-ops. The task that first needs a Make target must add it.

## Pull requests

- One work package per PR unless the program board records a coordinated exception.
- Do not open a “ready” PR, and do not declare a PR chain complete, while required CI is red.
- Update every affected `docs/` file, `CHANGELOG.md` unreleased section, and generated contracts in the same PR as the implementation.
- Handoff notes belong in the task file.

## Release tags and release notes

- Every release tag must include complete release notes (`docs/releases/<tag>.md`) describing all functionality differences from the previous release.
- Release notes must cover additions, behavior changes, bug fixes, removals, security changes, REST changes, MCP changes, proxy semantics, TLS/CA, configuration/schema, deployment, compatibility, migrations, and known limitations.
- A `v*` tag is created only after Release `tag-gate` sees every required CI job green on that SHA.
- A raw commit list is not sufficient.
- Residual limitations live in `docs/known-limitations.md`. Do not claim Python-addon or privileged-mode completeness in 1.0.

## Documentation is mandatory

- Update affected architecture, API, MCP, configuration, security, operation, testing, deployment, task, and ADR documents in the same change as the implementation.
- Stale documentation is a defect and blocks task completion.
- Examples must be tested or generated where practical.
- Cross-file links in README and `docs/` use absolute HTTPS URLs (`https://github.com/hilather/go-lab-mitmproxy/blob/main/...`).
- Update `Last reviewed` metadata when a document receives a substantive review.

## Generated files

- Do not manually edit generated OpenAPI, JSON Schema, MCP manifest, mocks, golden capability maps, or generated documentation.
- Change the source model or specification and run the documented generation target.
- Generation verification must leave the worktree clean.

## Dependencies

- Prefer the Go standard library and small, well-maintained libraries.
- Pin direct dependencies and review transitive changes.
- Allowed 1.0 direct deps are listed in `docs/01-architecture.md`. New deps need a PR justification, license check (Apache-2.0 compatible), and an ADR if they take over a protocol boundary.
- No Prometheus client (`github.com/prometheus/*` forbidden). Metrics are hand-rolled OpenMetrics.
- No `github.com/elazarl/goproxy`, `github.com/google/martian`, or exec of `mitmdump`.

## Required completion commands

The implementation repository must provide equivalent targets for:

```text
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
make security-scan
make test-changelog
make web-test
make web-build
```

FND-001 required CI jobs: `format`, `lint`, `unit`, `documentation`. CFG-001 adds `config-compat`. API-001 adds `generated-file`. MCP-001 adds `parity`. DEP-001 adds `container-test`. UI-001 adds `web`. GA-001 requires the full set with no optional jobs.

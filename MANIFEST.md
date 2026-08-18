# Pack Manifest

## Root guidance

- `README.md`: operator-facing product page and documentation map.
- `START-HERE.md`: onboarding, five-minute path, and definition of done.
- `docs/README.md`: full documentation catalog (architecture, ADRs, tasks, contracts).
- `AGENTS.md`: mandatory repository instructions (integration tests, REST/MCP parity, green CI).
- `CONTRIBUTING.md`: contribution workflow.
- `SECURITY.md`: top-level security policy (GitHub private advisories).
- `CHANGELOG.md`: curated unreleased and release history.
- `RELEASE-NOTES-TEMPLATE.md`: complete between-tag functionality-difference template.
- `docs/known-limitations.md`: honest first-GA residual.
- `CI-FAILURE-HARDENING-TEMPLATE.md`: root-cause and pipeline-hardening record.

## Design documents

- `docs/01-architecture.md`
- `docs/02-proxy-semantics.md`
- `docs/03-flow-store.md`
- `docs/04-state-and-configuration.md`
- `docs/05-control-plane-and-parity.md`
- `docs/06-rest-api.md`
- `docs/07-mcp-api.md`
- `docs/08-security-architecture.md`
- `docs/09-observability.md`
- `docs/10-testing-strategy.md`
- `docs/11-deployment.md`
- `docs/12-mitmweb-compat.md`
- `docs/13-integration-lab-add.md`
- `docs/14-release-engineering.md`
- `docs/15-documentation-governance.md`
- `docs/16-compatibility-and-versioning.md`
- `docs/17-error-model.md`
- `docs/18-roadmap-and-non-goals.md`
- `docs/19-acceptance-criteria.md`
- `docs/20-threat-model.md`
- `docs/21-standards-and-references.md`
- `docs/22-addon-pipeline.md`
- `docs/23-tls-and-certificates.md`
- `docs/24-filter-language.md`
- `docs/implementation-design.md`

## Architecture decisions

- `docs/adr/0001-use-go.md`
- `docs/adr/0002-in-tree-proxy-core.md`
- `docs/adr/0003-ephemeral-flows-and-gitops.md`
- `docs/adr/0004-shared-capability-registry.md`
- `docs/adr/0005-lab-static-bearer.md`
- `docs/adr/0006-pin-mcp-protocol-versions.md`
- `docs/adr/0007-starlark-not-cpython.md`
- `docs/adr/0008-mitmweb-compat-surface.md`
- `docs/adr/0009-privileged-modes-deferred.md`
- `docs/adr/0010-independent-rewrite.md`
- `docs/adr/0011-http2-now-http3-later.md`
- `docs/adr/0012-ca-is-secret-not-runtime.md`

## Agent task plans

See `docs/tasks/README.md` and `docs/tasks/00-program-board.md`.

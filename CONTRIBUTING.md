# Contributing

## Toolchain

- Go 1.26 (`go1.26.x`). The module path is `github.com/hilather/go-lab-mitmproxy`.
- Node **22.14.0** is required only for the embedded UI (`make web-build` / `make web-test`) after UI-001.
- `make lint` runs `go vet` and golangci-lint (version pinned in FND-001).
- `make security-scan` runs `golang.org/x/vuln/cmd/govulncheck` at the version pinned in FND-001.

See [AGENTS.md](AGENTS.md) for required Make targets. Tag notes live at `docs/releases/<tag>.md`.

## Development workflow

1. Choose or create a tracked task under [docs/tasks/](docs/tasks/).
2. Read the normative design documents and relevant ADRs.
3. Add or update tests that express the intended behavior, including **integration tests**.
4. Implement the smallest coherent change.
5. Update all affected documentation.
6. Run local CI-equivalent targets until they pass.
7. Submit a reviewable pull request with risk, test, compatibility, parity, and release-note information.
8. Do not mark the PR ready, and do not close a PR chain, while required CI is red. Fix and harden.

## Pull request requirements

Every pull request must state:

- Problem and intended outcome.
- Scope and explicit non-scope.
- Architectural invariants touched.
- Security and abuse considerations (especially TLS interception and CA handling).
- Test evidence, including integration and regression tests.
- REST/MCP parity impact.
- Configuration and compatibility impact.
- Documentation changed.
- Release-note entry or explicit reason that no externally observable behavior changed.
- Rollback strategy.

## Change sizing

Prefer small vertical slices that compile and pass tests. Do not merge partial public APIs, undocumented schema fields, or disabled tests as placeholders. Feature flags may be used only when their ownership, default, removal plan, and test matrix are documented.

## Commit and review discipline

- Keep generated changes separate when practical.
- Do not mix broad refactors with protocol changes unless necessary.
- Require review from owners of proxy semantics, TLS, API/MCP parity, security, and release engineering when those areas change.
- Resolve review findings in code, tests, and documentation rather than only in comments.

## Backward compatibility

Follow [docs/16-compatibility-and-versioning.md](docs/16-compatibility-and-versioning.md). Breaking changes require an ADR, migration instructions, release-note treatment, and the appropriate version increment.

## Independent rewrite

Do not copy files from `mitmproxy/mitmproxy`. Interop fixtures (HAR, HTTP transcripts, certificate vectors) must be independently authored or taken from public RFCs and our own captures.

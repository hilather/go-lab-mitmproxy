# FND-001: Repository Foundation

Status: not-started
Recommended owner: Go/platform agent
Dependencies: None
Exclusive ownership: root build files, initial module layout, CI skeleton
Wave: 0

## Goal

Create a minimal, secure, testable Go repository that encodes architectural boundaries before feature implementation.

## Design references

- [ ] `AGENTS.md`
- [ ] `docs/01-architecture.md`
- [ ] `docs/implementation-design.md`
- [ ] `docs/10-testing-strategy.md`
- [ ] `docs/14-release-engineering.md`
- [ ] ADR 0001, 0010

## Scope

- [ ] Initialize module `github.com/hilather/go-lab-mitmproxy` (Go 1.26).
- [ ] Create package directories from `docs/01-architecture.md` with `doc.go` and no cyclic dependencies.
- [ ] `cmd/labmitm` with `version` and `help` only; context-based shutdown stub.
- [ ] Makefile targets from `AGENTS.md`; unimplemented targets **fail closed**.
- [ ] CI: format, lint, unit, documentation (required). Other jobs fail-closed placeholders or omitted until the owning task adds them as required.
- [ ] License Apache-2.0 (already in tree), CODEOWNERS, pull-request template, changelog (exists).
- [ ] `internal/buildinfo` version/commit/MCP pin placeholder `2026-07-28`.
- [ ] `scripts/checkdocs` verifying required pack files and links.
- [ ] `internal/proxy/import_test.go` stub that will grow; at least forbid `internal/control` import from `internal/proxy` when those packages exist as stubs.

## Explicit non-scope

- Real proxy, REST, MCP, YAML schema (CFG-001).
- Dockerfile (DEP-001).

## Required tests

- [ ] Clean checkout passes format and unit checks.
- [ ] Documentation-link checking runs in CI.
- [ ] Race target has at least one concurrency test (can be a trivial mutex test).
- [ ] Fuzz-smoke executes a seed corpus (can be buildinfo or a stub).
- [ ] No required Make target is a no-op success.

## Documentation updates

- [ ] README five-minute path matches stub CLI.
- [ ] Changelog unreleased: repository foundation.

## CI requirements

- [ ] format, lint, unit, documentation green on the PR.

## Acceptance criteria

- Repository builds. Stub `labmitm version` prints module info.
- Pack files remain the source of truth.
- PR is not merged red.

## Handoff

Record Go patch version, golangci-lint version, govulncheck version, generate/verify strategy (even if only a fixture file).

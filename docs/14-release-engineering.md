# Release Engineering

Status: Proposed normative behavior
Owners: Release Engineering
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0001, 0006

## Required CI (no optional jobs)

Every job in `.github/workflows/ci.yml` (FND-001+) is required. No bypass, skip, `continue-on-error`, or unbounded retry. Actions pinned by full commit SHA. Go version from a single `GO_VERSION` matching `go.mod` and the Dockerfile.

Local equivalents: see [AGENTS.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/AGENTS.md).

FND-001 starts with format, lint, unit, documentation. Later tasks add jobs; they must be required as soon as they exist.

## Tag gate

`.github/workflows/release.yml` job `tag-gate` is the only tag path:

- All required CI green on the **exact** tag commit.
- Generated files current.
- `docs/releases/<tag>.md` exists with every heading from `RELEASE-NOTES-TEMPLATE.md`.
- Known limitations current.

## PR chains

The last PR in a chain must be green. If CI fails, fix and harden before merge. Record non-trivial failures under `docs/ci-failure-hardening/`.

## Surfaces compared between tags

OpenAPI, MCP manifest, capability table, config schema, CLI help, error catalog, metrics, defaults.

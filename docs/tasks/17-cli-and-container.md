# DEP-001: CLI Completion, Dockerfile, Compose

Status: not-started
Recommended owner: Platform agent
Dependencies: OBS-001, API-001
Exclusive ownership: `Dockerfile`, `examples/compose.smoke.yaml`, `scripts/test-container.sh`, serve flags
Wave: 7

## Goal

Hardened scratch image UID 65532, compose smoke, container-test CI job.

## Design references

- [ ] `docs/11-deployment.md`
- [ ] ADR 0009 (no extra caps)

## Scope

- [ ] `--proxy-listen`, `--management-listen`, `--shutdown-timeout`, `--pid-file`.
- [ ] Dockerfile multi-stage Go 1.26; UI stage later UI-001.
- [ ] `make test-container` fail-closed until this PR, then real.
- [ ] Secrets 0o644 documentation.

## Required tests

- [ ] Container: non-root, read-only, no caps, healthcheck.
- [ ] Smoke compose: validate config + health ready.

## Acceptance criteria

- `container-test` required CI job.

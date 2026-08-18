# CFG-001: Domain Model and Configuration

Status: not-started
Recommended owner: Config/schema agent
Dependencies: FND-001
Exclusive ownership: `internal/model`, `internal/config`, `testdata/config/**`, JSON Schema source
Wave: 1

## Goal

Fail-closed `labmitm.dev/v1alpha1` load/validate/canonicalize/hash with unknown fields rejected.

## Design references

- [ ] `docs/04-state-and-configuration.md`
- [ ] `docs/01-architecture.md` data model
- [ ] ADR 0003, 0009, 0011, 0012

## Scope

- [ ] Spec structs matching the YAML in docs/04.
- [ ] `KnownFields(true)`, byte sizes, durations, secret file refs.
- [ ] Reject reserved keys, `http3: true`, privileged modes, `.py` scripts.
- [ ] `labmitm validate` and `canonicalize`.
- [ ] Revision hash over canonical spec (paths not secret bytes).
- [ ] `internal/store` **interface** + Null implementation for PROXY-001.
- [ ] `make test-config-compat`.
- [ ] JSON Schema artifact path `api/jsonschema/labmitm.dev.v1alpha1.json` (generate now or fail-closed until generate exists — prefer generate in this PR if FND generate hook exists).

## Explicit non-scope

- Live plan/apply (STA-001).
- Serving listeners.

## Required tests

- [ ] Every field in the documented example YAML loads.
- [ ] Unknown field fails.
- [ ] Each reserved key fails (table).
- [ ] `http3: true`, `transparent` mode, `.py` script fail with stable codes.
- [ ] Canonicalize is deterministic.
- [ ] Integration: `labmitm validate` CLI on fixtures.

## Acceptance criteria

- Invalid bootstrap cannot be canonicalized as valid.
- Null store compiles for other lanes.

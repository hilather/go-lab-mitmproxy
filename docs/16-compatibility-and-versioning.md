# Compatibility and Versioning

Status: Proposed
Owners: Architecture, Release Engineering
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0006, 0008, 0010

## Public compatibility surfaces

- Proxy mode and HTTP/TLS semantics documented in this pack.
- Bootstrap `labmitm.dev/v1alpha1`.
- REST `/v1` paths, schemas, errors.
- MCP tool names `mitm_*`, resources `labmitm://…`, protocol `2026-07-28`.
- CLI flags, ports, filesystem paths.
- Metrics and audit schemas.
- mitmweb compat routes (best-effort; native `/v1` is the contract).
- HAR 1.2 export.

## Application semantic versioning

- Major: breaking public behavior.
- Minor: backward-compatible features.
- Patch: backward-compatible fixes; correctness fixes that change output must still be noted.

## Configuration versions

First GA ships **`labmitm.dev/v1alpha1` only**. Unknown `apiVersion` → `unsupported_protocol_version`. Unknown fields fail.

## REST

`/v1` additive optional fields preferred. Breaking removal requires `/v2` or flag day.

## MCP

First GA pins **2026-07-28 only**. `allowLegacyClients` is a lab overlay knob, not a second protocol claim.

## mitmweb compat

Compat may lag native `/v1`. Breaking compat requires notes. Dump format difference is permanent (JSONL vs Python dump).

## Deprecation

First deprecated release, replacement, earliest removal, tests.

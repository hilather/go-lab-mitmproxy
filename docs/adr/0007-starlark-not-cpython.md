# ADR 0007: Starlark scripts, not CPython

Status: Accepted
Date: 2026-08-18
Decisions: D11

## Context

mitmproxy addons are Python. Embedding CPython in a scratch non-root image conflicts with family container posture, supply chain, and sandboxing. Yaegi (Go interpret) executes unsandboxed Go.

## Decision

1.0 scripting is **Starlark** (`go.starlark.net`) plus in-tree Go addons covering built-in mitmproxy options. `.py` script paths fail validate. No CPython in the image.

## Consequences

- Existing mitmproxy Python addons will not run unmodified.
- Hook names are documented in `docs/22-addon-pipeline.md`.
- A future out-of-process Python bridge needs a new ADR and is not 1.0 GA.

## Alternatives considered

- Embed CPython: rejected.
- WASM plugins: possible 1.1; more toolchain for 1.0.
- Go plugins (`-buildmode=plugin`): poor scratch/static story; rejected.

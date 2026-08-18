# ADR 0003: Ephemeral flows and GitOps desired state

Status: Accepted
Date: 2026-08-18
Decisions: D3

## Context

Lab deployments need easy reset. Persisting flows to a directory would create a second source of truth (LabMail ADR 0003, LabDNS ADR 0003). mitmproxy `confdir` + `options.save` fights Git-mounted YAML.

## Decision

- Load one fail-closed `labmitm.dev/v1alpha1` document at startup.
- Config revision is a content hash of the canonical spec (secret paths, never values).
- Flow store has monotonic `storeGeneration`.
- Reset reloads YAML **and** wipes flows.
- The service never writes the bootstrap file.
- `POST /options/save` (compat) returns 403 `options_save_disabled`.

## Consequences

- Restart returns to Git-controlled state and an empty flow list.
- Operators who need a capture must export HAR/JSONL before reset.

## Alternatives considered

- Persist flows like `--save-stream-file` by default: rejected for GitOps.
- Write confdir from the API: rejected.

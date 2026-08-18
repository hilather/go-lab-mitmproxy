# ADR 0003: Ephemeral flows and GitOps desired state

Status: Accepted
Date: 2026-08-18
Decisions: D3

## Context

Lab deployments need easy reset and reviewable configuration. A durable flow-directory would create a second source of truth and contradict the family ephemeral invariant (LabDNS cache, LabMail inbox, TacLab event ring). Captured traffic is runtime evidence, not desired state.

## Decision

**D3 — Desired state is YAML; the flow store is not.**

- Load one fail-closed `labmitm.dev/v1alpha1` document at startup.
- Config revision is a content hash of the canonical spec (secrets as reference paths, never values; generated CA material is **not** in the spec hash).
- Flow store has its own monotonic `storeGeneration` (insert/delete/wipe/evict/breakpoint-state only).
- Reset reloads YAML **and** wipes flows (`store.ResetTo` / `Wipe` is the only epoch bump).
- The service never writes the bootstrap file.
- Spill on tmpfs is still RAM and is wiped on reset/restart. It is not a flow-directory.

## Consequences

- Restart returns to Git-controlled state and an empty flow store.
- Runtime experiments are easy to discard.
- Agents wait with `mitm_flows_wait` rather than depending on flows surviving a bounce.
- Multi-replica shared store is out of scope.
- Operators who want to keep a captured flow must export it before reset.
- Generate-mode CA rotates on restart/reset (operators who need a stable CA use `mode: files`).

## Alternatives considered

- Persist a flow-directory across restarts: survives accidental restart, but creates a second source of truth. Rejected.
- Embedded database: durable but conflicts with reset and Git ownership.
- Flow contents setting `drifted`: would make every captured request look like config drift. Rejected; `drifted` is `runtimeRevision != bootstrapRevision` only.

## Review triggers

Review this decision when a durable capture requirement is accepted, or when multi-replica flow sharing is proposed.

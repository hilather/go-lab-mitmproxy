# ADR 0009: Privileged capture modes deferred

Status: Accepted
Date: 2026-08-18
Decisions: D8

## Context

mitmproxy supports transparent, TUN, WireGuard, and local capture. Those typically need `NET_ADMIN`, extra devices, or host networking. The family default image is `cap_drop: ALL`, non-root, scratch.

## Decision

1.0 default image and schema **reject** `transparent`, `local`, `wireguard`, and `tun` modes. Task PRIV-001 (1.1) may add a **separate** privileged compose overlay and an ADR update. 1.0 modes: regular, reverse, socks5, upstream.

## Consequences

- Lab traffic capture uses explicit client proxy configuration (or reverse in front of a SUT).
- Feature parity for those modes is scheduled, not abandoned.

## Alternatives considered

- Grant caps in 1.0 image: rejected (family posture).
- Sidecar privileged helper in 1.0: extra process; deferred with PRIV-001.

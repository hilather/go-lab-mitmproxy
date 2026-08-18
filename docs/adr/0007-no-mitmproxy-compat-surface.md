# ADR 0007: No mitmproxy compat surface

Status: Accepted
Date: 2026-08-18
Decisions: D5

## Context

LabMail shipped `/email` only because `mcp-integration-lab` smoke (`maildevScenario`) asserted `GET /email` + Basic + subject. Searching `mcp-integration-lab` finds **zero** mitmproxy API clients. Shipping a fake mitmproxy REST (`/flows`, mitmweb, Python addon protocol) would freeze a surface we do not want.

The repo name `go-lab-mitmproxy` is historical naming (like `go-lab-maildev`), not a license to wrap mitmproxy.

## Decision

**D5 — Native management API is `/v1` + `POST /mcp` only.**

- No mitmproxy REST, no mitmweb, no Python addon protocol in 1.0.
- No wrapping, vendoring, or exec’ing the Python `mitmproxy` / `mitmdump` / `mitmweb` binary.
- Config reserved names reject `mitmproxy`, `mitmdump`, `mitmweb`, `addon`, `pythonaddon`, and related attack-tool keys.
- Catalog id is **`labmitm`** (no legacy id to preserve).
- `labmitm send` / `labmitm request` are **not** shipped (would look like an attack client). Tests use `internal/proxytest`.

Frozen capability table: [docs/07-control-plane-and-parity.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/07-control-plane-and-parity.md).

## Consequences

- Agents and new clients use `/v1` and `mitm_*` tools (`mitm_flows_wait`).
- No promise to track mitmproxy’s REST or addon API.
- The product is a lab appliance, not a drop-in binary swap for community mitmproxy.

## Alternatives considered

- mitmproxy REST compat shim: no consumer. Rejected.
- Wrap/exec Python mitmproxy: rejected by ADR 0002.
- Keep the product API named after mitmproxy paths: would lock the family out of `/v1` + MCP parity. Rejected.

## Review triggers

Review this decision when a concrete mitmproxy API client appears in the lab (it must not drive 1.0), or when a 1.1 compat shim is proposed with a named consumer.

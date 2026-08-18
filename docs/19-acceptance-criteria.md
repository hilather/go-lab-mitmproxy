# Product Acceptance Criteria

Status: Proposed
Owners: Product, Architecture, QA
Last reviewed: 2026-08-18 (design pack)

GA is a human tag on a **green** commit. Residual: [docs/known-limitations.md](known-limitations.md).

## Functional proxy

- Regular HTTP and HTTPS (CONNECT) intercept works with the lab CA.
- HTTP/2 on intercepted TLS works; translation to HTTP/1 upstream works.
- WebSocket capture and kill work.
- reverse, SOCKS5, and upstream modes pass documented interop tests.
- ignore/allow hosts, intercept/resume/kill, modify headers/body, map_local (sandboxed), map_remote, block_list, anticache, anticomp behave as specified.
- Client and server replay pass fixtures.
- HAR and JSONL export/import round-trip a documented fixture.
- Filter expressions in [docs/24-filter-language.md](24-filter-language.md) pass the table.

## State

- Startup loads strict YAML; unknown fields fail.
- Missing CA fail-closes serve.
- Mutations use expected revision and idempotency.
- Reset reloads bootstrap and wipes flows without rotating CA.
- Canonical export is deterministic and redacted.

## REST and MCP

- Every `PARITY_REQUIRED` capability has parity tests.
- REST contract and MCP conformance tests pass.
- Shared authorization and errors match.
- MCP Streamable HTTP validates Origin and protocol version.
- All mutations support planning and audit where documented.

## Security

- Unauthenticated management reads 401 on the image default.
- Container is non-root, read-only, capability-free, and scanned.
- CA key export default-off.
- Smuggling defenses on.
- No secret in export, logs, or public errors.

## Quality

- Every area has regression **and** integration coverage as required by [docs/10-testing-strategy.md](10-testing-strategy.md).
- Race, fuzz smoke, integration, parity, container, documentation, and security CI pass.
- No required CI job is optional.
- Documentation matches implementation.

## Release

- Release notes include all functionality differences from the previous tag.
- All CI passes on the tagged commit.
- Any previous CI failure has a documented fix and hardening when required.

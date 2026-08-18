# ADR 0010: Independent rewrite under Apache-2.0

Status: Accepted
Date: 2026-08-18

## Context

mitmproxy is MIT-licensed Python. This repository is Apache-2.0 like LabDNS/LabMail. Copying Python sources, mitmweb frontend, or dump codecs would create a derivative mix and fight “family-shaped” code.

## Decision

Independent clean-room rewrite from public documentation, RFCs, and our own interoperability tests. Do not copy files from `mitmproxy/mitmproxy`. Cite behavior references in `docs/21-standards-and-references.md`. HAR is the portable capture format.

## Consequences

- Dump format and JSON field names may differ; documented in compat notes.
- Agents must not paste upstream source into this tree.

## Alternatives considered

- Fork mitmproxy and add MCP: rejected (Python, no YAML GitOps, no scratch Go image).
- Dual license copy: still a Python product; rejected.

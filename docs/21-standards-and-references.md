# Standards and References

Status: Proposed
Owners: Architecture
Last reviewed: 2026-08-18 (design pack)

## Independent rewrite

LabMITM reimplements documented behavior. Do not copy source from `mitmproxy/mitmproxy` (MIT-licensed upstream; our work is Apache-2.0). See [ADR 0010](adr/0010-independent-rewrite.md).

## Upstream product (behavior reference)

- [mitmproxy documentation](https://docs.mitmproxy.org/stable/)
- [Proxy modes](https://docs.mitmproxy.org/stable/concepts/modes/)
- [Certificates](https://docs.mitmproxy.org/stable/concepts/certificates/)
- [Filter expressions](https://docs.mitmproxy.org/stable/concepts/filters/)
- [Options](https://docs.mitmproxy.org/stable/concepts/options/)
- [Protocols](https://docs.mitmproxy.org/stable/concepts/protocols/)
- mitmweb routes as publicly documented / observed from the running tool, re-specified in [docs/12-mitmweb-compat.md](12-mitmweb-compat.md)

Feature parity target: mitmproxy **11.x/12.x documented behavior** as of 2026-08-18, minus 1.0 residuals.

## RFCs and specs (non-exhaustive)

- RFC 9110 HTTP semantics, RFC 9112 HTTP/1.1, RFC 9113 HTTP/2
- RFC 6455 WebSockets
- RFC 1928 SOCKS5, RFC 1929 username/password
- RFC 2817 CONNECT
- RFC 8446 TLS 1.3, RFC 5246 TLS 1.2
- HAR 1.2
- MCP specification revision `2026-07-28`

## Family documents

- [mcp-integration-lab](https://github.com/hilather/mcp-integration-lab) `AGENTS.md` and `docs/architecture.md`
- LabDNS, LabMail, LabLDAP, TacLab capability-registry and GitOps model

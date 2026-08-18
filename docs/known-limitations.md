# Known Limitations (1.0)

Status: Proposed
Owners: Product
Last reviewed: 2026-08-18 (design pack)

LabMITM 1.0 is a laboratory intercepting proxy. It is not Python mitmproxy, not a production edge proxy, and not a complete copy of every mitmproxy mode.

## Intentional residuals

- **No CPython addons.** Scripts are Starlark `.star` files (ADR 0007).
- **No console TUI.** Use the SPA, REST, MCP, or dump CLI.
- **No HTTP/3 / QUIC** until H3-001. `http3: true` fails validate.
- **No transparent, TUN, WireGuard, or local-capture** in the default `cap_drop: ALL` image (ADR 0009).
- **No mitmproxy on-disk flow dump writer.** Export is JSONL + HAR.
- **Filter regexes are RE2**, not Python.
- **No `/options/save` to disk.** Desired state is Git-mounted YAML.
- **No `/processes` local-mode API.**
- **DNS reverse/proxy mode** is not 1.0 (LabDNS is the lab DNS).
- **LDAP proxyauth** is not 1.0.
- **Single replica**; flows are process memory (+ optional tmpfs spill).
- **MCP OAuth PRM** is not implemented. MCPJungle needs `allowLegacyClients: true`.
- **Certificate-pinned apps** will not intercept without SUT changes; use `ignore_hosts`.
- **`block_global` is false in the lab overlay** so published clients can connect; firewall the lab.

## Compatibility honesty

mitmweb clients that require binary flow dumps, UUID flow ids, or Python option persistence will need to move to `/v1` or HAR.

## After 1.0

See [docs/18-roadmap-and-non-goals.md](18-roadmap-and-non-goals.md) Phase 5.

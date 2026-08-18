# Security Policy

## Security posture

LabMITM is a privileged network service: an intercepting TLS proxy with a management API that can read, modify, and replay laboratory traffic. Secure defaults are mandatory. The default container drops all Linux capabilities, runs non-root, and does not enable transparent, TUN, WireGuard, or local-capture modes.

This is laboratory software. It is not a production edge proxy, WAF, or lawful-intercept system.

## Reporting vulnerabilities

Report security vulnerabilities through [GitHub private vulnerability reporting](https://github.com/hilather/go-lab-mitmproxy/security/advisories/new) on [`hilather/go-lab-mitmproxy`](https://github.com/hilather/go-lab-mitmproxy). Do not file vulnerabilities in the public issue tracker before coordinated disclosure.

Include, when possible: affected version or commit, deployment mode (container flags, proxy bind, auth profile), a minimal reproduction, and impact (open proxy, CA private-key leak, request smuggling, privilege escalation, secret in logs). Do not attach live tokens, CA keys, or captured production traffic.

We will acknowledge the report, assess severity, and coordinate a fix and disclosure window.

## Supported versions

| Version | Supported |
|---|---|
| Design-pack / unreleased `main` | Yes — current line |
| Pre-release development binaries (`dev` ldflags) | Best-effort until the first annotated tag |
| Any unreleased fork or modified image | No |

After a human tags `v1.0.0` (or `v1.0.0-rc.1`), that tag is the supported line.

## Minimum security requirements

- The proxy is not an open forward proxy to the public Internet by default in hardened profiles (`ssl_insecure` default false; upstream verification on; management authenticated).
- Management is authenticated (lab static bearer; optional Basic mapped to the same principal).
- REST and MCP share authentication, authorization, audit, and rate limiting.
- The CA private key is a mounted secret, never logged, never a metric label, and never a default MCP resource.
- HTTP request smuggling defenses stay on (`validateInboundHeaders` default true).
- Containers run as non-root with a read-only filesystem and no Linux capabilities.
- Dependencies, container images, and release artifacts are scanned.
- Captured bodies are lab data and may contain credentials; do not put URLs or hosts in metric labels.

See [docs/08-security-architecture.md](docs/08-security-architecture.md) and [docs/20-threat-model.md](docs/20-threat-model.md).

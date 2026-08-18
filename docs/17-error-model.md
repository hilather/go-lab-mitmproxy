# Error Model

Status: Proposed
Owners: Application, REST, MCP
Last reviewed: 2026-08-18 (design pack)

## Domain error shape

```json
{
  "code": "validation_failed",
  "message": "Candidate state is invalid.",
  "retryable": false,
  "fieldViolations": [
    {
      "path": "spec.proxy.modes[0].type",
      "code": "unsupported_mode",
      "message": "transparent is not supported in 1.0"
    }
  ],
  "currentRevision": "sha256:...",
  "remediation": "Use regular, reverse, socks5, or upstream."
}
```

Go constructors live in `internal/domainerr`. Do not invent synonyms.

Stable codes:

```text
validation_failed
revision_conflict
idempotency_conflict
not_found
method_not_allowed
already_exists
forbidden
unauthenticated
rate_limited
store_full
store_over_new_cap
cursor_stale
intercept_inactive
ca_missing
tls_error
upstream_unavailable
unsupported_capability
unsupported_protocol_version
options_save_disabled
timeout
internal_error
```

REST mapping: [docs/06-rest-api.md](06-rest-api.md). MCP uses the same `code` in JSON-RPC error data. Helpers: `capabilities.ProblemFrom`.

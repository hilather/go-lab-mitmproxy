# State and Configuration

Status: Proposed normative behavior
Owners: Configuration, Application
Last reviewed: 2026-08-18 (SEC-001)
Related ADRs: 0003

Desired state is YAML. The flow store is not. Config revision is a content hash of the canonical spec. Flow store has its own monotonic `storeGeneration`. Reset reloads YAML **and** wipes flows. See [docs/adr/0003-ephemeral-flows-and-gitops.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0003-ephemeral-flows-and-gitops.md).

STA-001 implements the HTTP-less control plane: `internal/compiler` (the **only** compiler), `internal/snapshot` (atomic immutable snapshot), `internal/audit` (ring + redact), and `internal/app.Service` (`Plan` / `Apply` / `Reset` / `Export`). API-001 REST (`internal/control/rest`) and MCP-001 (`internal/control/mcp`) call `app.Service` rather than reimplementing mutation.

## YAML rules (fail-closed)

- One document. UTF-8. No aliases/anchors. No duplicate keys. No multi-doc streams.
- Max file size 1 MiB.
- Unknown fields are errors (`yaml.Decoder.KnownFields(true)`).
- Durations: Go syntax (`30s`, `5m`).
- Byte sizes: binary units via `config.ByteSize` (`10MiB`, `256KiB`); bare numbers rejected.
- Secrets are **file references** only. Reject `environment:` as unknown. No `LABMITM_ALLOW_ENV_SECRETS`.
- `additionalProperties: false` in published JSON Schema.

Reserved / rejected keys (normalize strips dashes/underscores/case before compare):

```
socks, socks5, socks4, tproxy, transparent, reverseproxy, reverse_proxy,
publicca, trustedroot, mitmproxyaddon, addon, pythonaddon, exploit,
payloadgen, attack, sslstrip, hstsstrip
```

Plus any key that would imply wrapping the Python binary (`mitmproxy`, `mitmdump`, `mitmweb` as config sections).

## Bootstrap schema (normative 1.0)

```yaml
apiVersion: labmitm.dev/v1alpha1
kind: LabMITM
metadata:
  name: lab-proxy
spec:
  listeners:
    proxy:
      address: "127.0.0.1:8888"
    management:
      address: "127.0.0.1:8088"
      restPath: /v1
      mcpPath: /mcp
      tls:
        enabled: false
        certFile: ""
        keyFile: ""

  proxy:
    hostname: labmitm.lab
    admission:
      maxSessions: 256
      maxSessionsPerIP: 32
      maxInFlight: 64
      maxInFlightBytes: 64MiB
      sessionTimeout: 10m
      idleTimeout: 120s
      headerTimeout: 10s
      dialTimeout: 10s
      upstreamTimeout: 60s
    targets:
      denyCloudMetadata: true
      denyLinkLocal: true
      allowLoopback: true
      allowHosts: []
      denyHosts: []

  tls:
    intercept: false
    hosts: []
    ports: [443]
    ca:
      mode: generate
      certFile: ""
      keyFile: ""
    upstream:
      insecureSkipVerify: false
      extraCAFiles: []

  rules:
    enabled: false
    items: []

  store:
    maxFlows: 1000
    maxBytes: 256MiB
    maxBodyBytes: 1MiB
    fullPolicy: reject
    maxWait: 60s
    spillDirectory: ""
    spillThreshold: 256KiB

  ui:
    enabled: true

  management:
    auth:
      mode: bearer
      tokens:
        - id: admin
          secretFile: /run/secrets/labmitm-token
          role: administrator
          scopes: [mitm.read, mitm.write, mitm.admin, mitm.audit.read]
    mcp:
      allowLegacyClients: false
    originAllowlist: []
    bodyLimit: 1MiB
    requestsPerSecond: 32
    burst: 64
    maxConcurrent: 256

  observability:
    logLevel: info
    metrics:
      listen: "127.0.0.1:9090"
      publicPath: false
    audit:
      ring: 128
```

Empty `spec: {}` is valid and materializes the standalone loopback defaults (`127.0.0.1:8888` / `127.0.0.1:8088`). `labmitm validate --config` and `labmitm canonicalize --config [--format yaml|json]` implement this loader. `labmitm serve` (PROXY-001) binds the proxy after a successful load; invalid bootstrap binds nothing.

The published schema is [api/jsonschema/labmitm.dev.v1alpha1.json](https://github.com/hilather/go-lab-mitmproxy/blob/main/api/jsonschema/labmitm.dev.v1alpha1.json). `tls.upstream.verify` is not an input field; the only upstream verify knob is `insecureSkipVerify`. Export / `GET /v1/status` (later) materializes read-only `verify: !insecureSkipVerify`.

## Validate rules (fail closed)

- `listeners.proxy.address` and `listeners.management.address` (and `metrics.listen` when non-empty) must parse as `host:port` via `net.SplitHostPort` with port `1–65535`. Validate is offline (no DNS). `:8888` and `[::1]:8088` are legal. Empty listener address materializes the loopback defaults first, **not** `:8888`.
- Standalone defaults materialize to loopback (D10).
- `tls.ca.mode: files` requires existing cert+key; reject empty key PEM; reject world-writable key file; `mode: generate` with non-empty cert/key files → `validation_failed`.
- The only upstream input field is `insecureSkipVerify`. `tls.upstream.verify` is **not** on the struct.
- `tls.ports` entries are `1–65535`. After normalize, empty → `[443]`.
- `tls.intercept: true` with `ca.mode: files` and unreadable key → validate fail (do not bind).
- `rules.items[].id` unique and `[a-z0-9-]{1,64}`. Every item requires `phase` (`request`|`response`) and `action.type`. `action.delay` ∈ [0, 30s]. `action.status` empty or 400–599. Body replace ≤ 64 KiB in YAML.
- `store.maxBodyBytes` ≥ 1 KiB and ≤ `store.maxBytes`. `maxFlows` ≥ 1. `maxBytes` ≥ 1 MiB.
- Loader: `management.auth.mode: bearer` with **zero tokens is valid** (empty `spec: {}` must load). Each listed token requires `id`, `secretFile`, and `role`. Overlay `secretFile` paths that are not mounted do not fail validate; if the file exists, the first non-comment line must be ≥32 bytes (256 bits) after trim. `scopes` materialize to `[]` when omitted.
- Serve/bind (SEC-001): binding management with `mode: bearer` and zero usable tokens is **refused**. `dev-loopback-unauth` is rejected in the container default fixture (`testdata/container/config.yaml` is `mode: bearer`). Keep ADR 0005’s listen-refuse sentence as serve-time. Token files are reread on reset and apply.

## Revisions

```json
{
  "bootstrapRevision": "sha256:…",
  "runtimeRevision": "sha256:…",
  "generation": 4,
  "storeGeneration": 18,
  "drifted": false,
  "flowCount": 3,
  "storeBytes": 4096,
  "loadedAt": "2026-08-18T00:00:00Z"
}
```

- Revisions: SHA-256 of canonical normalized spec (secrets as reference paths, never values; generated CA material is **not** in the spec hash).
- `generation`: process-local config swap counter.
- `storeGeneration`: insert/delete/wipe/evict/breakpoint-state only.
- `drifted`: `runtimeRevision != bootstrapRevision`. Flows do **not** set `drifted`.

## Reset

`POST /v1/state:reset` / `mitm_state_reset`:

1. Re-read bootstrap path (never write it).
2. Validate + compile. On failure, leave current config **and** flows unchanged.
3. Preflight store options and CA load/generate.
4. `store.ResetTo` — the only epoch bump.
5. Atomically swap snapshot, clear idempotency LRU, increment `generation`.
6. In-flight proxy sessions keep the old snapshot until the request ends; new accepts load the new one.
7. Audit `state.reset`.

Restart is equivalent: process memory dies; generate-mode CA is new; spill wiped on next start.

## Plan / apply operations

```json
{
  "expectedRevision": "sha256:…",
  "idempotencyKey": "01J…",
  "reason": "enable login breakpoint",
  "force": false,
  "operations": [
    {
      "op": "replaceRules",
      "rules": { "enabled": true, "items": [] }
    }
  ]
}
```

| `op` | Body | Notes |
|---|---|---|
| `replaceStoreCaps` | `store`: `{maxFlows, maxBytes, maxBodyBytes, fullPolicy}` | Shrink + `reject` fails unless `force` |
| `replaceAdmission` | `admission` object | Live on next accept for the session gate, CONNECT dial timeout, and pinned tunnel idle/session deadlines. `http.Server.IdleTimeout` / `ReadHeaderTimeout` and the process-wide cleartext `Transport` stay at Start (`Options.Spec`). |
| `replaceTLS` | `tls` object | Recompile CA/host list; in-flight CONNECT unchanged |
| `replaceRules` | `rules` object | `{}` / empty items + `enabled: false` is stock capture |
| `replaceTargets` | `targets` object | Live on next request |

`:plan` is dry-run. `:apply` requires `expectedRevision`. Idempotency: key + identity (`reason` + canonical operations). Failures not cached. `revision_conflict` → 409. Listener **addresses** are not live-applyable; change YAML and reset.

Idempotency LRU default 256; reset clears it.

## Compiler, snapshot, and `app.Service`

`internal/compiler.Compile` is the only spec → snapshot path. It:

1. `config.Normalize` + `config.Validate` (copy-on-write).
2. Hashes canonical JSON (`sha256:…`). Generated CA material is **not** in the hash.
3. Builds `rules.Engine` from `spec.rules`.
4. Generates or loads the lab CA (`tlsmitm.Authority`). Generate-mode mints even when `intercept: false` so `GetCA` works. `replaceRules` / `replaceAdmission` / `replaceTargets` / `replaceStoreCaps` reuse the previous CA handle when the TLS spec is unchanged. `replaceTLS` and `Reset` recompile (generate-mode rotates).

`internal/snapshot.Store` holds active / previous / bootstrap behind atomic pointers. The proxy loads once per request / CONNECT (`Options.Snapshots`) and pins spec, engine, CA, and store epoch for the session. In-flight sessions keep the pointer they loaded; new accepts see the swapped snapshot. An in-flight `Insert` after `ResetTo` uses the accept-time epoch and is discarded (`ErrStaleEpoch`).

`internal/app.Service` is HTTP-less (no `net/http`, no MCP types, no Dial). Mutations copy Canonical, apply typed operations, compile a full candidate, then `Store.Swap` only after success. Failures leave config **and** flows unchanged. Reset rereads the bootstrap path, preflights store options (including spill), `store.ResetTo` (the only epoch bump), swaps, and clears the idempotency LRU.

`internal/audit` is a bounded ring (default 128) plus optional hook. Secrets, bearer tokens, and PEM private keys (`BEGIN` + `PRIVATE`) are redacted. Hook delivery failure is counted and never fail-closes.

## Startup

```text
read file
 -> reject unknown fields and reserved names
 -> decode versioned schema
 -> normalize names, durations, byte sizes, defaults
 -> validate cross-references and policy constraints
 -> compile snapshot (rules index; CA generate or load)
 -> compute bootstrap and runtime revisions
 -> wipe configured spill path
 -> bind proxy then management
 -> write pid file
```

A failed validate/compile exits non-zero and binds nothing.

Shutdown: `Accepting()=false` (ready goes unready) → drain in-flight proxy sessions up to `--shutdown-timeout` → close management → wipe spill → exit.

## Compatibility promise

`labmitm.dev/v1alpha1` is fail-closed; additive fields only after schema bump or explicit defaulting ADR.

# TLS Interception

Status: Proposed normative behavior
Owners: TLS, Proxy, Security
Last reviewed: 2026-08-23 (D62 h2c CONNECT intercept AfterAck)
Related ADRs: 0002, 0009, 0012

Package `internal/tlsmitm`. Only this package and `internal/proxy` touch `crypto/tls` on the data plane. Management TLS (optional) lives in `internal/control/rest` like LabMail. `internal/tlsmitm` must **not** Dial.

TLS-001 implements generate/files CA, per-host leaf mint, and dual handshake. Handshake failure closes both sides and does not fall back to a blind tunnel (D20). STA-001 compiles the CA into the immutable snapshot (`internal/compiler`); `replaceTLS` recompiles the handle (generate-mode rotates) and in-flight CONNECT sessions keep the Authority they pinned at accept. `app.Service.GetCA` / `GET /v1/ca` return the cert PEM only (never the key).

## CA

| `spec.tls.ca.mode` | Behavior |
|---|---|
| `generate` (default) | At compile, create an ECDSA P-256 CA in memory. Not written to disk. Not in config export. Restart = new CA (clients must re-download). |
| `files` | Load `certFile` + `keyFile` (PEM). Both required and must resolve at load. Reject empty key PEM. Reject if the key file mode is world-writable (`mode&0002 != 0`) when the process can `stat` it. Key file is read once into memory; never logged. Reject if cert is not CA (`BasicConstraintsValid && IsCA` + `KeyUsageCertSign`). Accept RSA ≥2048 or ECDSA P-256/P-384. |

Generated CA template (frozen):

```
Subject: CN=LabMITM Lab CA, O=LabMITM, OU=laboratory-only
BasicConstraints: CA:true (critical)
IsCA: true
KeyUsage: CertSign | CRLSign
MaxPathLen: 0
NotBefore: now-5m
NotAfter: now+10y
Serial: 128-bit crypto/rand
```

**Never** embed a CA key in the repo, image, or `testdata/` used by `go:embed` into the production binary. Test PEMs live under `testdata/tls/` and are loaded only by `*_test.go`.

## Leaf minting

```
Subject: CN=<sni or CONNECT host>
DNSNames or IPAddresses: SNI / host
ExtKeyUsage: ServerAuth
KeyUsage: DigitalSignature
NotBefore: now-5m
NotAfter: now+24h
Issuer: lab CA
Key: ECDSA P-256 (new per host, LRU 256 by lowercase host)
```

Leaf `NotAfter: now+24h` is long enough for a lab session. LRU eviction of a live host mints a new leaf on the next CONNECT, not mid-connection.

`GetConfigForClient` on the client-facing `tls.Server`:

1. Read `ClientHelloInfo.ServerName` (fallback: CONNECT host).
2. Reject empty SNI **and** empty CONNECT host.
3. Mint or LRU-get leaf.
4. Return `tls.Config{Certificates, NextProtos: <session snapshot>, MinVersion: tls.VersionTLS12}`.

Handshake NextProtos come from the session snapshot, not Authority compile (D46). Empty `nextProtos` (and flag-off `protocols.http2`) materialize `[]string{"http/1.1"}`. When `protocols.http2.enabled` is true the **client-facing leaf** advertises `["h2","http/1.1"]`. Origin NextProtos are `["h2","http/1.1"]` only when `protocols.http2.origin` **and** the inner leaf negotiated `h2` (`handshakeOriginNextProtos(spec, innerALPN)`, D64). Inner `http/1.1` never offers origin `h2`. Flag-off (or origin `http/1.1`) keeps D32/D44 transcode: one HTTP/1.1 origin TCP, mutex through body drain, `MaxConnsPerHost: 1`. Origin `h2` multiplexes inner streams on that one CONNECT TCP via `http2x.NewOriginTransport` (refuse-redial; D44 mutex is not used). A second origin TCP per stream is forbidden (D27). `compileCA` may still reuse the CA when the TLS spec is unchanged.

Upstream: `tls.Client(rawConn, &tls.Config{ServerName: sni, RootCAs: pool, NextProtos: <session snapshot>, MinVersion: tls.VersionTLS12, InsecureSkipVerify: spec.tls.upstream.insecureSkipVerify})`.

`RootCAs`: system pool (`x509.SystemCertPool`) plus `spec.tls.upstream.extraCAFiles`. If `insecureSkipVerify: true`, still record `TLSInfo.UpstreamVerified=false` and audit `tls.upstream_insecure` once per host per process hour (rate-limited), never per request.

The only upstream input field is `insecureSkipVerify`. `tls.upstream.verify` is **not** on the struct (`KnownFields(true)` rejects it). Export / `GET /v1/status` materializes read-only `verify: !insecureSkipVerify`.

## Intercept enablement

```yaml
tls:
  intercept: false          # master switch; default off
  hosts: []                 # empty + intercept true = all CONNECT hosts
  ports: [443]              # only these CONNECT ports attempt TLS (D20)
```

`intercept: false` → raw CONNECT tunnel. `intercept: true` with a host list → only listed hosts **and** listed ports attempt TLS; other CONNECTs tunnel. Empty `hosts` + `intercept: true` = all hosts on `ports`. Empty `ports` after normalize materializes `[443]`.

Handshake failure (client or upstream) on an intercept-eligible CONNECT: close both sides; store metadata-only flow with `Error=tls_handshake` (client) or `Error=upstream_tls` (origin verify/handshake); increment `labmitm_tls_intercepts_total{result=...}`. **No silent fallback to a blind tunnel** (D20). Client-facing h2c CONNECT uses the same order: 2xx HEADERS, then `serveInterceptConn` on the framed stream (no HTTP/1.1 200); handshake failure RSTs/closes the stream and does not splice DATA to origin.

Golden: `CONNECT 127.0.0.1:80` with `intercept: true` and default ports → raw tunnel (`intercepted=false`). `CONNECT 127.0.0.1:443` to a plaintext listener with intercept on → `Error=tls_handshake`.

Changing intercept/CA/ports requires compile (apply `replaceTLS` or reset). In-flight CONNECT sessions keep the snapshot they loaded at accept.

## Client trust

Operators download `GET /v1/ca` (`application/x-pem-file`, scope `mitm.read` — **not** on the unauthenticated data plane) or use the UI “Download lab CA” button and install it in the system / browser / language trust store. Document `curl --proxy http://127.0.0.1:8888 --cacert labmitm-ca.pem https://app.lab/`. There is no “click through” bypass in the appliance itself. Health/UI copy must say the CA is not served on `:8888`.

If the inner client negotiated `http/1.1` (flag off, or flag on but the client did not offer `h2`) and then sends an HTTP/2 preface: close both sides; store flow `Error=http2_inner`. When `protocols.http2.enabled` and the leaf ALPN is `h2`, `innerHTTP` runs `http2x.ServeClient` (`extendedConnect` off) or `http2x.ServeConn` with `PrefaceFull` + `ENABLE_CONNECT_PROTOCOL` (`extendedConnect` on). Each GET/POST stream is one captured flow (`Protocol=h2`, `HTTP2.StreamID`). `roundTripInnerH2` must not write HTTP/1.1 to the client TLS conn and must not close CONNECT on a per-stream 502 (D53). Concurrent h2 streams serialize on the HTTP/1.1 origin conn (D44) unless origin also negotiated `h2`, in which case they multiplex on that one TCP without the D44 mutex (D64). Response `WaitPaused` runs after the origin body is drained and, on the h1 origin path, the mutex is released. Nested inner CONNECT without `:protocol` and illegal h2 `Upgrade: websocket` stay RST `PROTOCOL_ERROR` with no flow (D48 remainder). With `extendedConnect`, inner `:protocol=websocket` transcodes to origin HTTP/1.1 Upgrade when origin is h1, or origin RFC 8441 Extended CONNECT when origin is h2; success is inner `:status=200` then DATA / `wsx` (D63). Other `:protocol` values RST, no flow. Replay of an h2 flow follows the **live** origin flag: off → HTTP/1.1 origin-form, leading-`:` stripped; on → origin ALPN `h2` then `http/1.1` on one Dial. `HTTP2.Pushed` stays false. When `protocols.http2.grpcDecode` is on, captured gRPC bodies are decoded after drain (`internal/grpcx`; fail-open; grpc-web opaque). The decoded tree is not re-encoded on replay.

Inner HTTP/1.1 `Upgrade: websocket` that the origin answers with `101` uses the same path as cleartext: flag-off bidirectional copy; flag-on `protocols.websocket.inspectFrames` `wsx` pumps (D67). HTTP/1.1 inner `RoundTrip` failure writes `502` and closes both sides.

**Residual:** intercepting TLS **breaks origin mTLS** (the origin sees the lab’s upstream client cert, which 1.0 does not present) and **breaks certificate pinning** in the SUT. Document in [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/known-limitations.md). Do not add client-cert passthrough in 1.0.

## CA private key handling

1. Generate-mode: lives in `snapshot` memory only. Not in revision hash. Not in export. Not in metrics. `fmt.Sprintf` / slog of `tls.Certificate` must not print `PrivateKey`.
2. Files-mode: read via `os.ReadFile` at compile; keep parsed `crypto.Signer` in memory; do not retain PEM bytes after parse.
3. Tests: `internal/tlsmitm` redaction test fails if a log buffer contains `BEGIN` + `PRIVATE`.
4. Container: key file bind-mounted `0o644` is acceptable (UID 65532 cannot read `0o600` root-owned files). Prefer tmpfs secret.
5. Operators confirm the live CA via `GET /v1/status` fields `ca.mode`, `ca.spkiSha256`, `ca.subject`, `ca.notAfter` after a generate-mode restart.

## Related documents

- CONNECT session: [docs/02-proxy-semantics.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md)
- Security: [docs/10-security-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/10-security-architecture.md)
- Status CA fields: [docs/08-rest-api.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/08-rest-api.md)

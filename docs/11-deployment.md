# Deployment

Status: Proposed normative behavior
Owners: Platform, Operations
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0001, 0003, 0009, 0012

## CLI

```text
labmitm serve --config=/etc/labmitm/config.yaml
              [--proxy-listen ADDR] [--management-listen ADDR|off]
              [--shutdown-timeout 5s] [--pid-file /tmp/labmitm.pid]
labmitm validate --config=...
labmitm canonicalize --config=... [--format yaml|json]
labmitm healthcheck --url=http://127.0.0.1:8081/v1/health/ready
labmitm ca generate --out=DIR
labmitm version
labmitm help
labmitm mcp-stdio --config ... --token-file ...
```

Invalid bootstrap or missing CA does **not** bind proxy or management.

`SIGTERM`/`SIGINT`: stop proxy accept, drain (deadline), then HTTP, then store wipe of spill files.

## Hardened container

```
USER 65532:65532
EXPOSE 8080/tcp 8081/tcp
ENTRYPOINT ["/labmitm"]
CMD ["serve", "--config=/etc/labmitm/config.yaml"]
HEALTHCHECK CMD ["/labmitm", "healthcheck", "--url=http://127.0.0.1:8081/v1/health/ready"]
```

Posture:

- Image `ghcr.io/hilather/labmitm`
- Non-root UID `65532:65532`
- scratch/static, read-only root
- `cap_drop: ALL`, `no-new-privileges:true`
- tmpfs `/tmp`
- no shell, no Docker socket
- Container ports **8080 / 8081**
- Optional SOCKS `10800/tcp` if the mode is enabled

UI-001: Node **22.14.0** stage copies `web/dist` before `go build`.

## Reference compose

Host ports in mcp-integration-lab: `LABMITM_PROXY_PORT` default **18880**, `LABMITM_WEB_PORT` default **18081**. Bind-mounted secrets **0o644**.

```yaml
services:
  labmitm:
    image: ghcr.io/hilather/labmitm:local
    command: ["serve", "--config=/etc/labmitm/config.yaml"]
    ports:
      - "18880:8080/tcp"
      - "18081:8081/tcp"
    volumes:
      - ./labmitm.yaml:/etc/labmitm/config.yaml:ro
      - ./ca:/var/lib/labmitm/ca:ro
      - ./labmitm-token:/run/secrets/labmitm-token:ro
    read_only: true
    tmpfs: ["/tmp"]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    user: "65532:65532"
    healthcheck:
      test: ["CMD", "/labmitm", "healthcheck", "--url=http://127.0.0.1:8081/v1/health/ready"]
      interval: 5s
      timeout: 3s
      retries: 12
      start_period: 3s
```

Privileged modes are not enabled here (ADR 0009).

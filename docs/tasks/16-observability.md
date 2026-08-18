# OBS-001: Observability

Status: not-started
Recommended owner: Observability agent
Dependencies: PROXY-001
Exclusive ownership: `internal/observability`, metrics catalog, `labmitm healthcheck`
Wave: 3 (can start after PROXY; ready semantics complete after TLS+API)

## Goal

slog JSON events, hand-rolled OpenMetrics, live/ready semantics from docs/09.

## Design references

- [ ] `docs/09-observability.md`
- [ ] `docs/11-deployment.md` healthcheck

## Scope

- [ ] Metric names frozen in docs/09.
- [ ] No prometheus client import test.
- [ ] `labmitm healthcheck`.
- [ ] Ready = proxy bound + CA loaded + store up + management bound or off.

## Required tests

- [ ] OpenMetrics parse + label policy (no URLs).
- [ ] Ready false during shutdown.
- [ ] **Integration:** scrape listener on 127.0.0.1:0.

## Acceptance criteria

- Healthcheck CLI used by DEP-001 Dockerfile.

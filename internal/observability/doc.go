// Package observability adapts metrics and structured logs.
//
// It is a leaf: no domain, snapshot, or control-plane imports. Callers
// increment catalog metrics, emit stable slog JSON events, and evaluate
// health facts. Telemetry never blocks the proxy; overflow is dropped and
// counted. Metrics are hand-rolled OpenMetrics — no Prometheus client.
package observability

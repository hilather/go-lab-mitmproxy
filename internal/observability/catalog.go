package observability

import (
	"encoding/json"
	"sort"
)

// CatalogID is the versioned metrics/events document identifier.
// Rename or semantic change of a catalog metric requires a new ID or a
// documented deprecation window.
const CatalogID = "labmitm.dev/metrics/v1alpha1"

// CatalogRelPath is the generated catalog artifact.
const CatalogRelPath = "api/metrics/v1alpha1.json"

// Kind is a catalog metric type.
type Kind string

const (
	KindCounter   Kind = "counter"
	KindGauge     Kind = "gauge"
	KindHistogram Kind = "histogram"
)

// Frozen metric names. These are an operational compatibility surface.
const (
	MetricProxySessionsTotal    = "labmitm_proxy_sessions_total"
	MetricProxyRejectedTotal    = "labmitm_proxy_rejected_total"
	MetricSocksSessionsTotal    = "labmitm_socks_sessions_total"
	MetricFlowsTotal            = "labmitm_flows_total"
	MetricTLSInterceptsTotal    = "labmitm_tls_intercepts_total"
	MetricRuleHitsTotal         = "labmitm_rule_hits_total"
	MetricStoreFlows            = "labmitm_store_flows"
	MetricStoreBytes            = "labmitm_store_bytes"
	MetricStoreEvictions        = "labmitm_store_evictions_total"
	MetricStoreFullTotal        = "labmitm_store_full_total"
	MetricStoreWaiters          = "labmitm_store_waiters"
	MetricHTTPRequestsTotal     = "labmitm_http_requests_total"
	MetricHTTPRequestDuration   = "labmitm_http_request_duration_seconds"
	MetricMCPCallsTotal         = "labmitm_mcp_calls_total"
	MetricAuthFailuresTotal     = "labmitm_auth_failures_total"
	MetricAuditEventsTotal      = "labmitm_audit_events_total"
	MetricTelemetryDropped      = "labmitm_telemetry_dropped_total"
	MetricH2TrailerDroppedTotal = "labmitm_h2_trailer_dropped_total"
)

// Frozen structured-log event names.
const (
	EventProxyAccepted    = "proxy.accepted"
	EventProxyRejected    = "proxy.rejected"
	EventProxySessionEnd  = "proxy.session_end"
	EventTLSIntercept     = "tls.intercept"
	EventTLSUpstreamInsec = "tls.upstream_insecure"
	EventStoreInserted    = "store.inserted"
	EventStoreDeleted     = "store.deleted"
	EventStoreWiped       = "store.wiped"
	EventStoreFull        = "store.full"
	EventRuleHit          = "rule.hit"
	EventFlowPaused       = "flow.paused"
	EventFlowResumed      = "flow.resumed"
	EventHTTPRequest      = "http.request"
	EventMCPCall          = "mcp.call"
	EventAuthFailure      = "auth.failure"
	EventAuthSuccess      = "auth.success"
	EventStateReset       = "state.reset"
	EventStateApply       = "state.apply"
)

// AllowedLabels is the default bounded label set. Metric definitions may
// use only a subset. Subjects, addresses, hosts, and client IPs are never allowed.
var AllowedLabels = []string{
	"action",
	"capability",
	"code_class",
	"component",
	"event",
	"intercepted",
	"reason",
	"result",
	"scheme",
	"tool",
}

// ForbiddenLabels must never appear on a catalog metric or recorded sample.
var ForbiddenLabels = []string{
	"actor",
	"actor_id",
	"address",
	"authorization",
	"body",
	"client",
	"client_ip",
	"cookie",
	"data",
	"detail",
	"err",
	"error",
	"error_text",
	"flow_id",
	"from",
	"host",
	"idempotency",
	"idempotency_key",
	"message",
	"password",
	"peer",
	"pem",
	"raw",
	"remote_addr",
	"set_cookie",
	"source_ip",
	"src",
	"src_ip",
	"subject",
	"to",
}

// MetricDef is one catalog row.
type MetricDef struct {
	Name   string   `json:"name"`
	Kind   Kind     `json:"kind"`
	Help   string   `json:"help"`
	Labels []string `json:"labels"`
	Unit   string   `json:"unit,omitempty"`
}

// EventDef is one stable structured-log event.
type EventDef struct {
	Name   string   `json:"name"`
	Fields []string `json:"fields"`
}

// Document is the versioned catalog artifact.
type Document struct {
	ID              string      `json:"id"`
	Version         string      `json:"version"`
	AllowedLabels   []string    `json:"allowedLabels"`
	ForbiddenLabels []string    `json:"forbiddenLabels"`
	Metrics         []MetricDef `json:"metrics"`
	Events          []EventDef  `json:"events"`
}

// EventFields is the frozen slog JSON field set.
var EventFields = []string{
	"timestamp", "level", "event", "component", "request_id", "flow_id",
	"host", "host_class", "capability", "result", "error_code", "duration_ms",
	"store_generation",
}

// Metrics returns the frozen first-GA catalog in stable name order.
func Metrics() []MetricDef {
	defs := []MetricDef{
		{Name: MetricProxySessionsTotal, Kind: KindCounter, Help: "Proxy sessions that ended.", Labels: []string{"result"}},
		{Name: MetricProxyRejectedTotal, Kind: KindCounter, Help: "Proxy requests rejected before forward.", Labels: []string{"reason"}},
		{Name: MetricSocksSessionsTotal, Kind: KindCounter, Help: "SOCKS CONNECT handshake outcomes.", Labels: []string{"result"}},
		{Name: MetricFlowsTotal, Kind: KindCounter, Help: "Captured flows.", Labels: []string{"scheme", "intercepted", "result"}},
		{Name: MetricTLSInterceptsTotal, Kind: KindCounter, Help: "TLS intercept handshake outcomes.", Labels: []string{"result"}},
		{Name: MetricRuleHitsTotal, Kind: KindCounter, Help: "First-match rule actions that fired.", Labels: []string{"action"}},
		{Name: MetricStoreFlows, Kind: KindGauge, Help: "Flows currently in the inbox.", Labels: nil},
		{Name: MetricStoreBytes, Kind: KindGauge, Help: "Resident inbox bytes.", Labels: nil},
		{Name: MetricStoreEvictions, Kind: KindCounter, Help: "Oldest-flow evictions.", Labels: nil},
		{Name: MetricStoreFullTotal, Kind: KindCounter, Help: "Capture drops because the inbox was full (proxy still forwarded).", Labels: nil},
		{Name: MetricStoreWaiters, Kind: KindGauge, Help: "Blocked Wait callers.", Labels: nil},
		{Name: MetricHTTPRequestsTotal, Kind: KindCounter, Help: "Management HTTP requests.", Labels: []string{"capability", "code_class"}},
		{Name: MetricHTTPRequestDuration, Kind: KindHistogram, Help: "Management HTTP latency.", Labels: []string{"capability"}, Unit: "seconds"},
		{Name: MetricMCPCallsTotal, Kind: KindCounter, Help: "MCP tool invocations.", Labels: []string{"tool", "result"}},
		{Name: MetricAuthFailuresTotal, Kind: KindCounter, Help: "Management authentication failures.", Labels: []string{"reason"}},
		{Name: MetricAuditEventsTotal, Kind: KindCounter, Help: "Audit ring records.", Labels: []string{"event"}},
		{Name: MetricTelemetryDropped, Kind: KindCounter, Help: "Telemetry samples dropped under backpressure or policy.", Labels: []string{"reason"}},
		{Name: MetricH2TrailerDroppedTotal, Kind: KindCounter, Help: "HTTP/2 request trailers dropped when transcoding onto HTTP/1.1 origin.", Labels: nil},
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Name < defs[j].Name })
	for i := range defs {
		defs[i].Labels = append([]string(nil), defs[i].Labels...)
		sort.Strings(defs[i].Labels)
	}
	return defs
}

// Events returns the frozen structured-log event catalog.
func Events() []EventDef {
	names := []string{
		EventProxyAccepted, EventProxyRejected, EventProxySessionEnd,
		EventTLSIntercept, EventTLSUpstreamInsec,
		EventStoreInserted, EventStoreDeleted, EventStoreWiped, EventStoreFull,
		EventRuleHit, EventFlowPaused, EventFlowResumed,
		EventHTTPRequest, EventMCPCall,
		EventAuthFailure, EventAuthSuccess,
		EventStateReset, EventStateApply,
	}
	out := make([]EventDef, len(names))
	for i, n := range names {
		out[i] = EventDef{Name: n, Fields: append([]string(nil), EventFields...)}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LookupMetric returns the catalog definition for name.
func LookupMetric(name string) (MetricDef, bool) {
	def, ok := metricIndex[name]
	return def, ok
}

var metricIndex = func() map[string]MetricDef {
	defs := Metrics()
	m := make(map[string]MetricDef, len(defs))
	for _, d := range defs {
		m[d.Name] = d
	}
	return m
}()

// Catalog returns the versioned document.
func Catalog() Document {
	return Document{
		ID:              CatalogID,
		Version:         "v1alpha1",
		AllowedLabels:   append([]string(nil), AllowedLabels...),
		ForbiddenLabels: append([]string(nil), ForbiddenLabels...),
		Metrics:         Metrics(),
		Events:          Events(),
	}
}

// RenderCatalog is the generated JSON artifact.
func RenderCatalog() ([]byte, error) {
	b, err := json.MarshalIndent(Catalog(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

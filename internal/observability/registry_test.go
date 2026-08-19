package observability

import (
	"bytes"
	"strings"
	"testing"
)

func TestRegistryEmitsCatalogMetrics(t *testing.T) {
	r := NewRegistry()
	r.Inc(MetricProxySessionsTotal, map[string]string{"result": "ok"}, 1)
	r.Inc(MetricProxyRejectedTotal, map[string]string{"reason": "socks"}, 1)
	r.Inc(MetricFlowsTotal, map[string]string{"scheme": "http", "intercepted": "false", "result": "ok"}, 1)
	r.Set(MetricStoreFlows, nil, 3)
	r.Inc(MetricHTTPRequestsTotal, map[string]string{"capability": "health.ready", "code_class": "2xx"}, 1)
	v, ok := r.Get(MetricProxySessionsTotal, map[string]string{"result": "ok"})
	if !ok || v != 1 {
		t.Fatalf("sessions=%v ok=%v", v, ok)
	}
	var buf bytes.Buffer
	if err := r.WriteOpenMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, MetricProxySessionsTotal) || !strings.Contains(out, `result="ok"`) {
		t.Fatalf("openmetrics scrape missing session series:\n%s", out)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "# EOF") {
		t.Fatalf("missing OpenMetrics EOF:\n%s", out)
	}
	if strings.Contains(strings.ToLower(out), "subject") || strings.Contains(out, "1.2.3.4") {
		t.Fatalf("scrape leaked subject/ip:\n%s", out)
	}
}

func TestRegistryRejectsSubjectAndClientIP(t *testing.T) {
	r := NewRegistry()
	r.Inc(MetricFlowsTotal, map[string]string{"scheme": "http", "intercepted": "false", "result": "ok", "host": "secret.example"}, 1)
	if _, ok := r.Get(MetricFlowsTotal, map[string]string{"scheme": "http", "intercepted": "false", "result": "ok", "host": "secret.example"}); ok {
		t.Fatal("host label must not be stored")
	}
	r.Inc(MetricHTTPRequestsTotal, map[string]string{"capability": "health.live", "code_class": "2xx", "client_ip": "192.0.2.1"}, 1)
	if _, ok := r.Get(MetricHTTPRequestsTotal, map[string]string{"capability": "health.live", "code_class": "2xx", "client_ip": "192.0.2.1"}); ok {
		t.Fatal("client_ip must not be stored")
	}
	dropped, ok := r.Get(MetricTelemetryDropped, map[string]string{"reason": "forbidden_label"})
	if !ok || dropped < 2 {
		t.Fatalf("expected forbidden_label drops, got %v ok=%v", dropped, ok)
	}
}

func TestRegistrySeriesCap(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < MaxSeriesPerMetric+10; i++ {
		r.Inc(MetricAuditEventsTotal, map[string]string{"event": "e-" + itoa(i)}, 1)
	}
	n := 0
	for _, s := range r.Snapshot() {
		if s.Name == MetricAuditEventsTotal {
			n++
		}
	}
	if n > MaxSeriesPerMetric {
		t.Fatalf("series=%d cap=%d", n, MaxSeriesPerMetric)
	}
	if r.Dropped() == 0 {
		t.Fatal("expected cardinality drops")
	}
}

func TestUnusedExportQueueDoesNotDrop(t *testing.T) {
	r := NewRegistry()
	if r.Export() != nil {
		t.Fatal("export queue must stay nil until EnableExport")
	}
	for i := 0; i < DefaultQueueSize+8; i++ {
		r.Inc(MetricProxySessionsTotal, map[string]string{"result": "ok"}, 1)
	}
	if r.Dropped() != 0 {
		t.Fatalf("unused export must not count drops, dropped=%d", r.Dropped())
	}
}

func TestExportBackpressureDoesNotBlock(t *testing.T) {
	r := NewRegistry()
	q := r.EnableExport(1)
	for i := 0; i < q.Cap()+8; i++ {
		r.Inc(MetricProxySessionsTotal, map[string]string{"result": "ok"}, 1)
	}
	v, ok := r.Get(MetricProxySessionsTotal, map[string]string{"result": "ok"})
	if !ok || v < 1 {
		t.Fatalf("counter lost under export backpressure v=%v", v)
	}
	if q.Dropped() == 0 {
		t.Fatal("expected export queue drops")
	}
}

func TestCheckLabelsUnknownMetric(t *testing.T) {
	if err := CheckLabels("not_a_metric", nil); err == nil {
		t.Fatal("expected unknown_metric")
	}
}

func TestBoundedResultHelpers(t *testing.T) {
	if ProxySessionResult("OK") != "ok" || ProxySessionResult("nope") != "rejected" {
		t.Fatal("session result")
	}
	if ProxyRejectReason("socks") != "socks" || ProxyRejectReason("socks_auth") != "socks_auth" ||
		ProxyRejectReason("socks_command") != "socks_command" || ProxyRejectReason("origdest") != "origdest" || ProxyRejectReason("x") != "admission" {
		t.Fatal("reject reason")
	}
	if SocksSessionResult("OK") != "ok" || SocksSessionResult("nope") != "denied" {
		t.Fatal("socks result")
	}
	if TLSInterceptResult("upstream_tls") != "upstream_tls" || TLSInterceptResult("x") != "tls_handshake" {
		t.Fatal("tls result")
	}
	if CodeClass(200) != "2xx" || CodeClass(404) != "4xx" || CodeClass(503) != "5xx" {
		t.Fatal("code class")
	}
	if ClassifyHost("app.lab") != "lab" || ClassifyHost("192.0.2.1") != "ip" || ClassifyHost("example.com") != "public" {
		t.Fatal("host class")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	n := len(b)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		b[n] = '-'
	}
	return string(b[n:])
}

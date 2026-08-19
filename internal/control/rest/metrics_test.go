package rest

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/auth"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/observability"
)

func TestMetricsPublicPathDisabled(t *testing.T) {
	s, _ := newTestServer(t)
	got := doReq(t, s.Handler(), http.MethodGet, "/v1/metrics", "")
	requireProblem(t, got, http.StatusNotFound, "not_found")
}

func TestMetricsPublicPathOpenMetrics(t *testing.T) {
	svc := bootTestApp(t)
	reg := observability.NewRegistry()
	reg.Inc(observability.MetricProxySessionsTotal, map[string]string{"result": "ok"}, 1)
	s, err := New(Config{
		Service:       svc,
		RatePerSec:    -1,
		PublicMetrics: true,
		Metrics:       reg,
		Auth:          auth.Static(testToken, "admin", model.RoleAdministrator),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := doReq(t, s.Handler(), http.MethodGet, "/v1/metrics", "")
	requireStatus(t, got, http.StatusOK)
	if !strings.Contains(got.Header().Get("Content-Type"), "openmetrics") {
		t.Fatalf("content-type=%s", got.Header().Get("Content-Type"))
	}
	body := got.Body.String()
	if !strings.Contains(body, observability.MetricProxySessionsTotal) || !strings.Contains(body, "# EOF") {
		t.Fatalf("body=%s", body)
	}
}

func TestHTTPRequestMetrics(t *testing.T) {
	svc := bootTestApp(t)
	reg := observability.NewRegistry()
	s, err := New(Config{
		Service:    svc,
		RatePerSec: -1,
		Metrics:    reg,
		Auth:       auth.Static(testToken, "admin", model.RoleAdministrator),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := doReq(t, s.Handler(), http.MethodGet, "/v1/health/live", "")
	requireStatus(t, got, http.StatusOK)
	v, ok := reg.Get(observability.MetricHTTPRequestsTotal, map[string]string{
		"capability": "health.live",
		"code_class": "2xx",
	})
	if !ok || v < 1 {
		t.Fatalf("http requests=%v ok=%v", v, ok)
	}
}

func TestReadyOverride(t *testing.T) {
	svc := bootTestApp(t)
	s, err := New(Config{
		Service:    svc,
		RatePerSec: -1,
		Ready:      func() bool { return false },
		Auth:       auth.Static(testToken, "admin", model.RoleAdministrator),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := doReq(t, s.Handler(), http.MethodGet, "/v1/health/ready", "")
	requireStatus(t, got, http.StatusServiceUnavailable)
	st := doReq(t, s.Handler(), http.MethodGet, "/v1/status", "")
	requireStatus(t, st, http.StatusOK)
	if decodeJSON(t, st)["ready"] != false {
		t.Fatalf("status.ready must match health hook: %s", st.Body.String())
	}
}

func TestAuthFailureMetric(t *testing.T) {
	svc := bootTestApp(t)
	reg := observability.NewRegistry()
	s, err := New(Config{
		Service:    svc,
		RatePerSec: -1,
		Metrics:    reg,
		Auth:       auth.Static(testToken, "admin", model.RoleAdministrator),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := doReqAuth(t, s.Handler(), http.MethodGet, "/v1/status", "", "wrong-token-wrong-token-xxxx")
	requireStatus(t, got, http.StatusUnauthorized)
	v, ok := reg.Get(observability.MetricAuthFailuresTotal, map[string]string{"reason": "invalid"})
	if !ok || v < 1 {
		t.Fatalf("auth failures=%v ok=%v", v, ok)
	}
}

func TestHTTPRequestLogIncludesRequestIDAndAuthSuccess(t *testing.T) {
	svc := bootTestApp(t)
	var buf bytes.Buffer
	log := observability.NewLogger(&buf, observability.LevelInfo).WithSync()
	s, err := New(Config{
		Service:    svc,
		RatePerSec: -1,
		Logger:     log,
		Auth:       auth.Static(testToken, "admin", model.RoleAdministrator),
	})
	if err != nil {
		t.Fatal(err)
	}
	const wantID = "req-obs-001-correlate"
	req := httptestReq(http.MethodGet, "/v1/status", "")
	req.Header.Set(headerRequestID, wantID)
	got := doRaw(s.Handler(), req)
	requireStatus(t, got, http.StatusOK)
	if got.Header().Get(headerRequestID) != wantID {
		t.Fatalf("response X-Request-ID=%q", got.Header().Get(headerRequestID))
	}
	out := buf.String()
	if !strings.Contains(out, observability.EventAuthSuccess) {
		t.Fatalf("missing auth.success: %s", out)
	}
	if !strings.Contains(out, observability.EventHTTPRequest) {
		t.Fatalf("missing http.request: %s", out)
	}
	if !strings.Contains(out, wantID) {
		t.Fatalf("http.request must carry request_id: %s", out)
	}
}

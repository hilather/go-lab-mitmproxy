package rest

import (
	"net/http"
	"testing"
)

func TestOriginAllowlist(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()

	missing := httptestReq(http.MethodGet, "/v1/health/live", "")
	missing.Header.Del("Authorization")
	requireStatus(t, doRaw(h, missing), http.StatusOK)

	req := httptestReq(http.MethodGet, "/v1/health/live", "")
	req.Header.Del("Authorization")
	req.Header.Set("Origin", "http://127.0.0.1:8088")
	requireStatus(t, doRaw(h, req), http.StatusOK)

	req = httptestReq(http.MethodGet, "/v1/health/live", "")
	req.Header.Del("Authorization")
	req.Header.Set("Origin", "https://evil.example")
	requireProblem(t, doRaw(h, req), http.StatusForbidden, "forbidden")

	req = httptestReq(http.MethodGet, "/v1/health/live", "")
	req.Header.Del("Authorization")
	req.Header.Set("Origin", "file://localhost")
	requireProblem(t, doRaw(h, req), http.StatusForbidden, "forbidden")

	req = httptestReq(http.MethodGet, "/v1/health/live", "")
	req.Header.Del("Authorization")
	req.Header.Set("Origin", "http://192.168.1.9:8088")
	requireProblem(t, doRaw(h, req), http.StatusForbidden, "forbidden")

	s.cfg.AllowedOrigins = []string{"http://192.168.1.9:8088"}
	req = httptestReq(http.MethodGet, "/v1/health/live", "")
	req.Header.Del("Authorization")
	req.Header.Set("Origin", "http://192.168.1.9:8088")
	requireStatus(t, doRaw(h, req), http.StatusOK)
}

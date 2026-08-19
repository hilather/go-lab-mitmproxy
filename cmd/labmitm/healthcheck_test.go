package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthcheckOK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health/ready" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()
	var stdout, stderr bytes.Buffer
	code := healthcheckCmd([]string{"--url", ts.URL + "/v1/health/ready"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ok") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestHealthcheckNotReady(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()
	var stdout, stderr bytes.Buffer
	code := healthcheckCmd([]string{"--url", ts.URL + "/v1/health/ready"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit %d want 1 stderr=%q", code, stderr.String())
	}
}

func TestHealthcheckUnreachable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := healthcheckCmd([]string{"--url", "http://127.0.0.1:1/v1/health/ready"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit %d want 1 stderr=%q", code, stderr.String())
	}
}

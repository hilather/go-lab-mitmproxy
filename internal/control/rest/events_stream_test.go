package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEventsStreamHeaders(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/events/stream", nil)
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Authorization", "Bearer "+testToken)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("content-type=%q", ct)
	}
}

package rest

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
)

func TestCursorHMACAndStale(t *testing.T) {
	s, svc := newTestServer(t)
	h := s.Handler()
	for i := 0; i < 3; i++ {
		insertFlow(t, svc, "n.lab")
	}
	page := doReq(t, h, http.MethodGet, "/v1/flows?limit=1", "")
	requireStatus(t, page, http.StatusOK)
	cur, _ := decodeJSON(t, page)["nextCursor"].(string)
	if cur == "" {
		t.Fatal("missing nextCursor")
	}
	page2 := doReq(t, h, http.MethodGet, "/v1/flows?limit=1&cursor="+cur, "")
	requireStatus(t, page2, http.StatusOK)

	insertFlow(t, svc, "new.lab")
	stale := doReq(t, h, http.MethodGet, "/v1/flows?limit=1&cursor="+cur, "")
	p := requireProblem(t, stale, http.StatusBadRequest, "cursor_stale")
	if p["code"] == "validation_failed" {
		t.Fatal("cursor_stale must not wrap as validation_failed")
	}

	bad := doReq(t, h, http.MethodGet, "/v1/flows?cursor=not-a-cursor", "")
	requireProblem(t, bad, http.StatusBadRequest, "validation_failed")
}

func TestCursorRotatesOnReset(t *testing.T) {
	s, svc := newTestServer(t)
	s.cursorMu.Lock()
	key1 := append([]byte(nil), s.cursorKey...)
	s.cursorMu.Unlock()
	if _, err := svc.Reset(context.Background(), app.Actor{ID: "t", Transport: "direct"}, app.ResetIn{Reason: "hook"}); err != nil {
		t.Fatal(err)
	}
	s.cursorMu.Lock()
	key2 := append([]byte(nil), s.cursorKey...)
	s.cursorMu.Unlock()
	if bytes.Equal(key1, key2) {
		t.Fatal("Service.Reset must rotate the REST cursor HMAC key")
	}
	h := s.Handler()
	insertFlow(t, svc, "a.lab")
	insertFlow(t, svc, "b.lab")
	page := doReq(t, h, http.MethodGet, "/v1/flows?limit=1", "")
	cur, _ := decodeJSON(t, page)["nextCursor"].(string)
	reset := doReq(t, h, http.MethodPost, "/v1/state:reset", `{}`)
	requireStatus(t, reset, http.StatusOK)
	got := doReq(t, h, http.MethodGet, "/v1/flows?cursor="+cur, "")
	requireProblem(t, got, http.StatusBadRequest, "cursor_stale")
}

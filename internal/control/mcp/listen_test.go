package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func listenRPC(id int, proto string) string {
	return rpcCall(id, methodListen, map[string]any{
		"_meta": map[string]any{
			"io.modelcontextprotocol/protocolVersion": proto,
			"io.modelcontextprotocol/clientInfo": map[string]any{
				"name": "labmitm-test", "version": "dev",
			},
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		},
		"notifications": map[string]any{
			"resourceSubscriptions": []string{resourceFlows},
		},
	})
}

func TestListenAcknowledgesFlowsURI(t *testing.T) {
	s, svc := newTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := listenRPC(7, ProtocolVersion)
	req := httptest.NewRequest(http.MethodPost, DefaultPath, strings.NewReader(body)).WithContext(ctx)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(headerMethod, methodListen)
	req.Header.Set(headerProtocolVersion, ProtocolVersion)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Handler().ServeHTTP(rec, req)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(rec.Body.String(), "notifications/subscriptions/acknowledged") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(rec.Body.String(), "labmitm://flows") {
		t.Fatalf("ack missing uri: %s", rec.Body.String())
	}

	insertFlow(t, svc, "listen.lab")
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(rec.Body.String(), "notifications/resources/updated") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(rec.Body.String(), `"uri":"labmitm://flows"`) {
		t.Fatalf("missing URI-only notify: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"host":"listen.lab"`) {
		t.Fatal("listen must not include flow bodies")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("listen did not return")
	}
}

func TestListenRequiresPinnedProtocol(t *testing.T) {
	s, _ := newTestServer(t)
	rec := doRaw(t, s.Handler(), `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{}}`, map[string]string{
		"Content-Type":        "application/json",
		"Accept":              "text/event-stream",
		headerMethod:          methodListen,
		headerProtocolVersion: "2025-11-25",
	}, "127.0.0.1:1")
	requireRPCError(t, rec, http.StatusBadRequest, "validation_failed")
}

func TestListenPinWithLegacyClients(t *testing.T) {
	_, svc := newTestServer(t)
	s, err := New(Config{Service: svc, RatePerSec: -1, AllowLegacyClients: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"legacy-gateway","version":"0.0.1"}}}`
	initRec := doRaw(t, s.Handler(), initBody, map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json, text/event-stream",
	}, "127.0.0.1:1")
	if initRec.Code != http.StatusOK && initRec.Code != http.StatusAccepted {
		t.Fatalf("legacy initialize status=%d body=%s", initRec.Code, initRec.Body.String())
	}
	initRPC := decodeRPC(t, initRec)
	if _, ok := initRPC["error"]; ok {
		t.Fatalf("legacy initialize error: %s", initRec.Body.String())
	}
	result, _ := initRPC["result"].(map[string]any)
	if result == nil || result["protocolVersion"] == "" {
		t.Fatalf("legacy initialize missing protocolVersion: %s", initRec.Body.String())
	}

	badHeader := doRaw(t, s.Handler(), `{"jsonrpc":"2.0","id":2,"method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":["labmitm://flows"]}}}`, map[string]string{
		"Content-Type":        "application/json",
		"Accept":              "text/event-stream",
		headerMethod:          methodListen,
		headerProtocolVersion: "2025-11-25",
	}, "127.0.0.1:1")
	requireRPCError(t, badHeader, http.StatusBadRequest, "validation_failed")

	missing := doRaw(t, s.Handler(), `{"jsonrpc":"2.0","id":3,"method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":["labmitm://flows"]}}}`, map[string]string{
		"Content-Type": "application/json",
		"Accept":       "text/event-stream",
		headerMethod:   methodListen,
	}, "127.0.0.1:1")
	requireRPCError(t, missing, http.StatusBadRequest, "validation_failed")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	metaBody := listenRPC(4, ProtocolVersion)
	req := httptest.NewRequest(http.MethodPost, DefaultPath, strings.NewReader(metaBody)).WithContext(ctx)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(headerMethod, methodListen)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Handler().ServeHTTP(rec, req)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rec.Code == http.StatusBadRequest {
			t.Fatalf("listen with only _meta pin rejected: %s", rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "notifications/subscriptions/acknowledged") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("listen with only _meta pin rejected: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "notifications/subscriptions/acknowledged") {
		t.Fatalf("listen with only _meta pin did not ack: status=%d body=%s", rec.Code, rec.Body.String())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("meta-pin listen did not return")
	}
}

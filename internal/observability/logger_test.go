package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLoggerJSONFields(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, LevelInfo).WithSync()
	l.Log(Record{
		Event:           EventProxyAccepted,
		Component:       "proxy",
		FlowID:          "01TESTFLOWID00000000000000",
		Host:            "app.example.com",
		Result:          "ok",
		StoreGeneration: 3,
		Remote:          "192.0.2.55",
		Timestamp:       time.Unix(0, 0).UTC(),
	})
	s := buf.String()
	if strings.Contains(s, "192.0.2.55") {
		t.Fatalf("info must not log remote IP: %s", s)
	}
	if strings.Contains(s, "app.example.com") {
		t.Fatalf("info must not log raw Host: %s", s)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["event"] != EventProxyAccepted {
		t.Fatalf("event=%v", rec["event"])
	}
	if rec["flow_id"] != "01TESTFLOWID00000000000000" {
		t.Fatalf("flow_id=%v", rec["flow_id"])
	}
	if rec["host_class"] != "public" {
		t.Fatalf("host_class=%v", rec["host_class"])
	}
	if rec["store_generation"] != float64(3) {
		t.Fatalf("store_generation=%v", rec["store_generation"])
	}
	if _, ok := rec["timestamp"]; !ok {
		t.Fatalf("missing timestamp: %s", s)
	}
	for _, bad := range []string{"Authorization", "Cookie", "Set-Cookie", "BEGIN PRIVATE", "password"} {
		if strings.Contains(s, bad) {
			t.Fatalf("leaked %s: %s", bad, s)
		}
	}
}

func TestLoggerInfoUsesHostClassForLabSuffix(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, LevelInfo).WithSync()
	l.Log(Record{Event: EventProxySessionEnd, Host: "app.lab", Timestamp: time.Unix(0, 0).UTC()})
	s := buf.String()
	if strings.Contains(s, `"host":"app.lab"`) {
		t.Fatalf("info must not log raw lab Host: %s", s)
	}
	if !strings.Contains(s, `"host_class":"lab"`) {
		t.Fatalf("info should classify lab suffix: %s", s)
	}
}

func TestLoggerDebugKeepsRemoteAndHost(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, LevelDebug).WithSync()
	l.Log(Record{Event: EventProxySessionEnd, Host: "app.lab", Remote: "192.0.2.9", Timestamp: time.Unix(0, 0).UTC()})
	s := buf.String()
	if !strings.Contains(s, "192.0.2.9") {
		t.Fatalf("debug mode should keep remote: %s", s)
	}
	if !strings.Contains(s, "app.lab") {
		t.Fatalf("debug mode should keep host: %s", s)
	}
}

func TestLoggerDefaultWritesSync(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, LevelInfo)
	l.Log(Record{Event: EventStateReset, Result: "ok"})
	if !strings.Contains(buf.String(), EventStateReset) {
		t.Fatalf("default Log must write: %s", buf.String())
	}
}

func TestLoggerQueueDropDoesNotBlock(t *testing.T) {
	reg := NewRegistry()
	l := NewLogger(nil, LevelInfo).WithQueue(1).WithMetrics(reg)
	if !l.Queue().TrySend(Record{Event: EventHTTPRequest}) {
		t.Fatal("first enqueue")
	}
	done := make(chan struct{})
	go func() {
		l.Log(Record{Event: EventAuthFailure})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Log blocked on full queue")
	}
	if l.Queue().Dropped() == 0 || l.Dropped() == 0 {
		t.Fatal("expected drop")
	}
	if v, ok := reg.Get(MetricTelemetryDropped, map[string]string{"reason": "log"}); !ok || v < 1 {
		t.Fatalf("log overflow not counted: %v ok=%v", v, ok)
	}
}

func TestLoggerServeDrainsOnCancel(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, LevelInfo).WithQueue(8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		l.Serve(ctx)
		close(done)
	}()
	l.Log(Record{Event: EventStateApply, Result: "ok"})
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit")
	}
	if !strings.Contains(buf.String(), EventStateApply) {
		t.Fatalf("missing event: %s", buf.String())
	}
}

func TestParseLevel(t *testing.T) {
	if ParseLevel("DEBUG") != LevelDebug || ParseLevel("nope") != LevelInfo {
		t.Fatal("ParseLevel")
	}
}

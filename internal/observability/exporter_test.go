package observability

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestListenEmptyDisables(t *testing.T) {
	l, err := Listen("", NewRegistry())
	if err != nil || l != nil {
		t.Fatalf("empty listen: l=%v err=%v", l, err)
	}
}

func TestListenServesOpenMetrics(t *testing.T) {
	reg := NewRegistry()
	reg.Inc(MetricStoreEvictions, nil, 2)
	l, err := Listen("127.0.0.1:0", reg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = l.Shutdown(ctx)
	})
	url := "http://" + l.Addr() + "/metrics"
	var resp *http.Response
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = http.Get(url)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "openmetrics") {
		t.Fatalf("content-type=%s", resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if !strings.Contains(s, MetricStoreEvictions) || !strings.Contains(s, "# EOF") {
		t.Fatalf("body=%s", s)
	}
}

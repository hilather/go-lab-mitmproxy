package compat

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestMapFlowGolden(t *testing.T) {
	f := sampleHTTP2Flow()
	got, err := json.Marshal(MapFlow(f))
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(repoRoot(t), "testdata", "compat", "flow-get.json")
	want, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, got, want) {
		t.Fatalf("MapFlow mismatch\ngot:  %s\nwant: %s", compactJSON(t, got), compactJSON(t, want))
	}
}

func TestMapListGolden(t *testing.T) {
	got, err := json.Marshal(MapList([]*model.Flow{sampleHTTP2Flow()}))
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(repoRoot(t), "testdata", "compat", "flow-list.json")
	want, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, got, want) {
		t.Fatalf("MapList mismatch\ngot:  %s\nwant: %s", compactJSON(t, got), compactJSON(t, want))
	}
}

func TestMapFlowErrorNull(t *testing.T) {
	f := &model.Flow{ID: "01TEST", Method: "GET", URL: "http://h/", Host: "h", Scheme: "http", Protocol: model.FlowProtocolHTTP11}
	b, err := json.Marshal(MapFlow(f))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"error":null`)) {
		t.Fatalf("error must be JSON null: %s", b)
	}
	if !bytes.Contains(b, []byte(`"response":null`)) {
		t.Fatalf("open flow response must be JSON null: %s", b)
	}
}

func TestRESTRefsMatchSideTable(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range capabilities.CompatBindings() {
		for _, b := range c.REST {
			seen[b.RESTRef()] = true
		}
	}
	for _, ref := range []string{RefList, RefGet, RefDelete, RefClear, RefReplay, RefRequestContent, RefResponseContent} {
		if !seen[ref] {
			t.Errorf("side table missing RESTRef %s", ref)
		}
	}
	if len(seen) != 7 {
		t.Fatalf("side table REST refs=%d want 7", len(seen))
	}
}

func sampleHTTP2Flow() *model.Flow {
	start := time.Unix(1787155200, 123*int64(time.Millisecond)).UTC()
	end := time.Unix(1787155200, 200*int64(time.Millisecond)).UTC()
	return &model.Flow{
		ID:          "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		StartedAt:   start,
		CompletedAt: end,
		Method:      "GET",
		URL:         "https://app.lab/login",
		Host:        "app.lab",
		Scheme:      "https",
		Protocol:    model.FlowProtocolHTTP2,
		Status:      200,
		Intercepted: true,
		Request: model.HTTPMessage{
			Headers: []model.Header{
				{Name: ":method", Value: "GET"},
				{Name: ":authority", Value: "app.lab"},
				{Name: "user-agent", Value: "curl"},
			},
		},
		Response: model.HTTPMessage{
			Headers: []model.Header{{Name: "content-type", Value: "text/plain"}},
			Body:    []byte("ok"),
			Size:    2,
		},
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var xa, xb any
	if err := json.Unmarshal(a, &xa); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &xb); err != nil {
		t.Fatal(err)
	}
	ga, _ := json.Marshal(xa)
	gb, _ := json.Marshal(xb)
	return bytes.Equal(ga, gb)
}

func compactJSON(t *testing.T, raw []byte) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}

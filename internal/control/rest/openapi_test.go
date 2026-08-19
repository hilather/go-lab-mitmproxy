package rest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
)

func TestRenderOpenAPI(t *testing.T) {
	b, err := RenderOpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["openapi"] != OpenAPIVersion {
		t.Fatalf("openapi=%v", doc["openapi"])
	}
	paths, _ := doc["paths"].(map[string]any)
	if _, ok := paths["/v1/flows:wait"]; !ok {
		t.Fatal("missing wait path")
	}
	if _, ok := paths["/v1/ca"]; !ok {
		t.Fatal("missing ca path")
	}
	if _, ok := paths["/v1/flows/{id}:replay"]; !ok {
		t.Fatal("missing replay path")
	}
	for _, c := range capabilities.All() {
		for _, bind := range c.REST {
			if _, ok := paths[bind.Path]; !ok {
				t.Errorf("openapi missing %s", bind.Path)
			}
		}
	}
	for _, c := range capabilities.CompatBindings() {
		for _, bind := range c.REST {
			item, ok := paths[bind.Path].(map[string]any)
			if !ok {
				t.Errorf("openapi missing compat %s", bind.Path)
				continue
			}
			op, _ := item[strings.ToLower(bind.Method)].(map[string]any)
			if op == nil {
				t.Errorf("openapi missing compat %s %s", bind.Method, bind.Path)
				continue
			}
			if op["x-rest-only"] != true {
				t.Errorf("compat %s missing x-rest-only", bind.RESTRef())
			}
			if op["x-parity"] != "REST_ONLY_PROTOCOL" {
				t.Errorf("compat %s x-parity=%v", bind.RESTRef(), op["x-parity"])
			}
		}
	}
}

func TestRenderOpenAPIDoesNotPutCompatOnCatalogPaths(t *testing.T) {
	for _, c := range capabilities.All() {
		for _, b := range c.REST {
			if strings.Contains(b.Path, "/compat") {
				t.Errorf("catalog leaked compat path %s", b.Path)
			}
		}
	}
}

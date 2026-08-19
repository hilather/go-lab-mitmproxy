package capabilities

import (
	"encoding/json"
	"testing"
)

func TestRenderManifest(t *testing.T) {
	b, err := RenderManifest()
	if err != nil {
		t.Fatal(err)
	}
	var doc Manifest
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.APIVersion != ManifestAPIVersion || len(doc.Capabilities) != TableRowCount {
		t.Fatalf("manifest %+v", doc)
	}
	if doc.GeneratedBy != ManifestGeneratedBy {
		t.Fatalf("generatedBy=%q", doc.GeneratedBy)
	}
}

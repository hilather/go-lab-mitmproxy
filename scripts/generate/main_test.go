package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
	"github.com/hilather/go-lab-mitmproxy/internal/control/mcp"
	"github.com/hilather/go-lab-mitmproxy/internal/control/rest"
)

func TestPlannedFiles(t *testing.T) {
	files, err := plannedFiles()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range files {
		got[f.rel] = true
		if len(f.body) == 0 {
			t.Errorf("empty %s", f.rel)
		}
	}
	if !got[capabilities.ManifestRelPath] || !got[rest.OpenAPIRelPath] || !got[mcp.ManifestRelPath] {
		t.Fatalf("planned=%v", got)
	}
}

func TestCheckFilesStale(t *testing.T) {
	dir := t.TempDir()
	files, err := plannedFiles()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFiles(dir, files); err != nil {
		t.Fatal(err)
	}
	if err := checkFiles(dir, files); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, filepath.FromSlash(files[0].rel))
	if err := os.WriteFile(path, append(files[0].body, []byte("x")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkFiles(dir, files); err == nil {
		t.Fatal("expected stale")
	}
}

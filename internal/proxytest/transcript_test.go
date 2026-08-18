package proxytest

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadTranscript(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	script, err := loadTranscript(filepath.Join(root, "testdata", "proxy", "absolute-https.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(script) < 2 || script[0].kind != 'C' || script[len(script)-1].kind != 'S' {
		t.Fatalf("script %#v", script)
	}
	if !matchLine("HTTP/1.1 400 Bad Request", "HTTP/1.1 400 *") {
		t.Fatal("prefix match")
	}
}

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func testdataConfig(t *testing.T, elem ...string) string {
	t.Helper()
	parts := append([]string{repoRoot(t), "testdata", "config"}, elem...)
	return filepath.Join(parts...)
}

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labmitm", "version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "labmitm") {
		t.Fatalf("version output %q missing labmitm", stdout.String())
	}
}

func TestUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labmitm"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("stderr %q missing usage", stderr.String())
	}
}

func TestHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labmitm", "help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout.String(), "version") {
		t.Fatalf("help %q missing version", stdout.String())
	}
	if !strings.Contains(stdout.String(), "serve") {
		t.Fatalf("help %q missing serve", stdout.String())
	}
	if !strings.Contains(stdout.String(), "validate") || !strings.Contains(stdout.String(), "canonicalize") {
		t.Fatalf("help %q missing validate/canonicalize", stdout.String())
	}
}

func TestValidateAndCanonicalize(t *testing.T) {
	path := testdataConfig(t, "valid", "defaults.yaml")
	var stdout, stderr bytes.Buffer
	code := run([]string{"labmitm", "validate", "--config", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate exit %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ok revision=sha256:") {
		t.Fatalf("validate output %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"labmitm", "canonicalize", "--config", path, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("canonicalize exit %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"kind":"LabMITM"`) {
		t.Fatalf("canonicalize output %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"127.0.0.1:8888"`) {
		t.Fatalf("canonicalize missing loopback proxy bind: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	bad := testdataConfig(t, "invalid", "unknown-field.yaml")
	code = run([]string{"labmitm", "validate", "--config", bad}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("invalid validate exit %d want 1 stderr=%q", code, stderr.String())
	}
}

func TestValidateRequiresConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labmitm", "validate"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--config") {
		t.Fatalf("stderr %q missing --config", stderr.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labmitm", "not-a-command"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}

func TestServeRequiresConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labmitm", "serve"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--config") {
		t.Fatalf("stderr %q missing --config", stderr.String())
	}
}

func TestServeNoTokenFileFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labmitm", "serve", "--config", testdataConfig(t, "valid", "defaults.yaml"), "--token-file", "x"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2 (serve must not accept --token-file)", code)
	}
}

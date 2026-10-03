package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) (string, manifest) {
	t.Helper()
	root := t.TempDir()
	m := manifest{Contracts: map[string]string{}, Capabilities: map[string]coverage{}, Operations: map[string]coverage{}}
	for _, path := range append(append([]string{}, contractFiles...), "web/src/example.test.tsx") {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("contract"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range contractFiles {
		m.Contracts[path] = fmt.Sprintf("%x", sha256.Sum256([]byte("contract")))
	}
	c := coverage{Route: "/", Workflow: "inspect", Evidence: []evidence{{File: "src/example.test.tsx", Test: "sends the request"}}}
	m.Capabilities["flows.get"] = c
	m.Operations["replaceTLS"] = c
	return root, m
}

func TestCoverageFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*manifest)
		want string
	}{
		{"missing capability", func(m *manifest) { delete(m.Capabilities, "flows.get") }, "missing capability"},
		{"unknown capability", func(m *manifest) { m.Capabilities["invented"] = m.Capabilities["flows.get"] }, "unknown capability"},
		{"missing operation", func(m *manifest) { delete(m.Operations, "replaceTLS") }, "missing operation"},
		{"missing evidence", func(m *manifest) { c := m.Capabilities["flows.get"]; c.Evidence = nil; m.Capabilities["flows.get"] = c }, "behavioral evidence"},
		{"removed test file", func(m *manifest) {
			c := m.Capabilities["flows.get"]
			c.Evidence = []evidence{{File: "src/missing.test.tsx", Test: "gone"}}
			m.Capabilities["flows.get"] = c
		}, "evidence:"},
		{"contract change", func(m *manifest) { m.Contracts[contractFiles[0]] = "stale" }, "changed: review browser parity"},
		{"removed contract check", func(m *manifest) { delete(m.Contracts, contractFiles[0]) }, "contract review files"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, m := fixture(t)
			if err := validate(root, m, []string{"flows.get"}, []string{"replaceTLS"}); err != nil {
				t.Fatal(err)
			}
			tc.edit(&m)
			if err := validate(root, m, []string{"flows.get"}, []string{"replaceTLS"}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestNewOperationIsDiscovered(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "internal/model")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "operation.go"), []byte(`package model; const (OpNew = "newVerb"; Other = "ignore")`), 0o600); err != nil {
		t.Fatal(err)
	}
	ops, err := operationNames(root)
	if err != nil || len(ops) != 1 || ops[0] != "newVerb" {
		t.Fatalf("operations %v, error %v", ops, err)
	}
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckRepoDocuments(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(root); err != nil {
		t.Fatal(err)
	}
}

func TestCheckReportsMissingAndBroken(t *testing.T) {
	dir := t.TempDir()
	if err := Check(dir); err == nil {
		t.Fatal("expected missing documents")
	} else if !strings.Contains(err.Error(), "required documents missing") {
		t.Fatalf("error = %v", err)
	}

	// Minimal tree with a broken relative link.
	for _, rel := range RequiredRootDocs {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("# x\n\nSee [missing](no-such-file.md).\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := Check(dir); err == nil {
		t.Fatal("expected broken link")
	} else if !strings.Contains(err.Error(), "broken markdown links") {
		t.Fatalf("error = %v", err)
	}
}

func TestCheckReportsMissingMetadata(t *testing.T) {
	dir := t.TempDir()
	for _, rel := range RequiredRootDocs {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		body := "# x\n"
		if rel == "docs/01-architecture.md" {
			body = "# System Architecture\n\nNo metadata.\n"
		} else if strings.HasPrefix(rel, "docs/") && strings.HasSuffix(rel, ".md") && !strings.Contains(rel, "adr/") {
			body = "# x\n\nStatus: Proposed\nOwners: Test\nLast reviewed: 2026-08-18\n"
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := Check(dir); err == nil {
		t.Fatal("expected missing metadata")
	} else if !strings.Contains(err.Error(), "documentation metadata missing") {
		t.Fatalf("error = %v", err)
	}
}

func TestFuzzCorporaPresent(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkFuzzCorpora(root); err != nil {
		t.Fatal(err)
	}
}

func TestFuzzCorporaReportsMissing(t *testing.T) {
	dir := t.TempDir()
	if err := checkFuzzCorpora(dir); err == nil {
		t.Fatal("expected missing corpora")
	} else if !strings.Contains(err.Error(), "fuzz corpora missing") {
		t.Fatalf("error = %v", err)
	}
}

func TestCheckReportsKeepBothLeftovers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		rel     string
		body    string
		wantSub string
	}{
		{
			name:    "stale later PR",
			rel:     "docs/02-proxy-semantics.md",
			body:    numberedMeta + "\nUDP ASSOCIATE stays `05 07` until a later PR.\n",
			wantSub: "stale leftover",
		},
		{
			name:    "stale h2c still out",
			rel:     "docs/01-architecture.md",
			body:    numberedMeta + "\nClient-facing Extended CONNECT / h2c is still out.\n",
			wantSub: "stale leftover",
		},
		{
			name:    "duplicate related ADRs",
			rel:     "docs/12-testing-strategy.md",
			body:    numberedMeta + "Related ADRs: 0002\nRelated ADRs: 0002\n",
			wantSub: "consecutive duplicate line",
		},
		{
			name:    "duplicate table first cell",
			rel:     "docs/12-testing-strategy.md",
			body:    numberedMeta + "| Layer | What |\n|---|---|\n| Proxy protocol | a |\n| Proxy protocol | b |\n",
			wantSub: "duplicate table first cell",
		},
		{
			name: "consecutive keep-both bullets",
			rel:  "AGENTS.md",
			body: "# x\n\n" +
				"- HTTP/1.1 only on every hop in 1.0. No HTTP/2 or HTTP/3. `PRI * HTTP/2.0` is a hard close. 1.1 may enable inner hops.\n" +
				"- HTTP/1.1 only on every hop in 1.0. No HTTP/2 or HTTP/3. `PRI * HTTP/2.0` is a hard close. 1.2 may enable h2c.\n",
			wantSub: "consecutive keep-both list items",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if err := seedRequiredDocs(dir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, filepath.FromSlash(tc.rel))
			if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			err := Check(dir)
			if err == nil {
				t.Fatal("expected keep-both leftovers")
			}
			if !strings.Contains(err.Error(), "keep-both leftovers") || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

const numberedMeta = "# x\n\nStatus: Proposed\nOwners: Test\nLast reviewed: 2026-08-24\n\n"

func seedRequiredDocs(dir string) error {
	for _, rel := range RequiredRootDocs {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		body := "# x\n"
		if strings.HasPrefix(rel, "docs/") && strings.HasSuffix(rel, ".md") && !strings.Contains(rel, "adr/") {
			body = numberedMeta
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func TestCheckReportsInvalidExampleYAML(t *testing.T) {
	dir := t.TempDir()
	for _, rel := range RequiredRootDocs {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		body := "# x\n"
		if strings.HasPrefix(rel, "docs/") && strings.HasSuffix(rel, ".md") && !strings.Contains(rel, "adr/") {
			body = "# x\n\nStatus: Proposed\nOwners: Test\nLast reviewed: 2026-08-18\n"
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ex := filepath.Join(dir, "examples", "bad.yaml")
	if err := os.MkdirAll(filepath.Dir(ex), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ex, []byte("\tservices:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Check(dir); err == nil {
		t.Fatal("expected invalid example")
	} else if !strings.Contains(err.Error(), "invalid example YAML") {
		t.Fatalf("error = %v", err)
	}
}

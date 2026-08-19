package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateNotesRequiresHeadings(t *testing.T) {
	if err := validateNotes("# empty\n"); err == nil {
		t.Fatal("expected missing headings")
	} else if !strings.Contains(err.Error(), "Highlights") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateNotesRepoFile(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(root, "docs", "releases", "v1.0.0-rc.1.md"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNotes(string(body)); err != nil {
		t.Fatal(err)
	}
}

func TestValidateNotesRejectsPlaceholder(t *testing.T) {
	var b strings.Builder
	for _, h := range requiredNoteHeadings() {
		b.WriteString("## ")
		b.WriteString(h)
		b.WriteString("\n\nNot a public edge proxy.\n")
	}
	ok := b.String()
	if err := validateNotes(ok); err != nil {
		t.Fatal(err)
	}
	if err := validateNotes(ok + "\nTODO\n"); err == nil {
		t.Fatal("expected placeholder")
	}
}

func TestEvaluateChecks(t *testing.T) {
	jobs := requiredCIJobs()
	var runs []checkRun
	for _, j := range jobs {
		runs = append(runs, checkRun{Name: "CI / " + j, Status: "completed", Conclusion: "success", HeadSHA: "abc"})
	}
	if err := evaluateChecks(jobs, runs, "abc"); err != nil {
		t.Fatal(err)
	}
	if err := evaluateChecks(jobs, runs[:len(runs)-1], "abc"); err == nil {
		t.Fatal("expected missing job")
	}
	bad := append([]checkRun(nil), runs...)
	bad[0].Conclusion = "failure"
	if err := evaluateChecks(jobs, bad, "abc"); err == nil {
		t.Fatal("expected failed job")
	}
	blank := append([]checkRun(nil), runs...)
	for i := range blank {
		blank[i].HeadSHA = ""
	}
	if err := evaluateChecks(jobs, blank, "abc"); err == nil {
		t.Fatal("expected empty HeadSHA to fail")
	}
}

func TestRequiredCIJobsHaveNoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, j := range requiredCIJobs() {
		if seen[j] {
			t.Fatalf("duplicate %s", j)
		}
		seen[j] = true
	}
}

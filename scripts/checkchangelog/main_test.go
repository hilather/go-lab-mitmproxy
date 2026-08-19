package main

import "testing"

func TestCheckChangelogRequiresEntry(t *testing.T) {
	err := checkChangelog([]string{"internal/proxy/server.go"})
	if err == nil {
		t.Fatal("expected missing changelog")
	}
	err = checkChangelog([]string{"internal/proxy/server.go", "CHANGELOG.md"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCheckChangelogIgnoresTestsAndUnobservable(t *testing.T) {
	if err := checkChangelog([]string{"internal/perf/soak_test.go", "docs/01-architecture.md"}); err != nil {
		t.Fatal(err)
	}
}

func TestObservableRel(t *testing.T) {
	if !observableRel("docs/known-limitations.md") {
		t.Fatal("known-limitations should be observable")
	}
	if !observableRel("docs/releases/v1.0.0-rc.1.md") {
		t.Fatal("release notes should be observable")
	}
	if !observableRel("docs/14-integration-lab.md") {
		t.Fatal("integration-lab BOM should be observable")
	}
	if observableRel("internal/perf/soak_test.go") {
		t.Fatal("tests are not observable")
	}
	if observableRel("CHANGELOG.md") {
		t.Fatal("changelog itself is not an observable trigger")
	}
}

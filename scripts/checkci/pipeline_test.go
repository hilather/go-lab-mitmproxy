package checkci

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Exercise the workflow's run shell with a failing make and a successful tee.
// A log-producing test step must retain the producer's nonzero exit status.
func TestWorkflowLoggingPipelinesFailClosed(t *testing.T) {
	workflow, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	shell := "bash --noprofile --norc -e {0}" // GitHub's unspecified Linux shell.
	if match := regexp.MustCompile(`(?m)^    shell: (.+)$`).FindSubmatch(workflow); match != nil {
		shell = string(match[1])
	}
	pipelines := regexp.MustCompile(`(?m)^        run: (make (?:test|test-race|test-fuzz-smoke)\b[^\n]*\| tee ([^\s]+))$`).FindAllSubmatch(workflow, -1)
	if len(pipelines) != 3 {
		t.Fatalf("expected three logged test pipelines; got %d", len(pipelines))
	}
	for _, pipeline := range pipelines {
		t.Run(string(pipeline[2]), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "make"), []byte("#!/bin/sh\necho producer-failed\nexit 23\n"), 0700); err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(dir, "step.sh")
			if err := os.WriteFile(script, []byte(string(pipeline[1])+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			args := strings.Fields(shell)
			for i := range args {
				if args[i] == "{0}" {
					args[i] = script
				}
			}
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("workflow masked failing make: %s", output)
			}
			logged, logErr := os.ReadFile(filepath.Join(dir, string(pipeline[2])))
			if logErr != nil || !strings.Contains(string(logged), "producer-failed") {
				t.Fatalf("failure log missing: %s %v", logged, logErr)
			}
		})
	}
}

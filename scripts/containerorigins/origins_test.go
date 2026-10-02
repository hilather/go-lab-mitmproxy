package containerorigins

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainerOriginsStartupProtocol(t *testing.T) {
	for _, kind := range []string{"ready", "exit", "hung"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			fake := `#!/usr/bin/env bash
case "$3" in
ready) echo 'origin ready http=:8080 https=:8443'; exec sleep 10;;
exit) echo 'fixture TLS initialization failed' >&2; exit 7;;
hung) exec sleep 10;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(fake), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", `source "$1"; PATH="$2:$PATH"; wait_container_origin "$3" 0.2`, "test", "../container-diagnostics.sh", dir, kind)
			output, err := cmd.CombinedOutput()
			if kind == "ready" {
				if err != nil {
					t.Fatalf("readiness event: %v %s", err, output)
				}
			} else {
				if err == nil {
					t.Fatal("failed startup accepted")
				}
				if !strings.Contains(string(output), "origin did not emit valid readiness") {
					t.Fatalf("missing startup diagnostic: %s", output)
				}
			}
			if kind == "exit" && !strings.Contains(string(output), "fixture TLS initialization failed") {
				t.Fatal("fixture early exit lost stderr")
			}
		})
	}
}

func TestContainerFailureDiagnosticsBoundedAndIdentifyStage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "https.stderr"), []byte(strings.Repeat("old fixture line\n", 100)+"actionable fixture failure\n"), 0600); err != nil {
		t.Fatal(err)
	}
	script := `source "$1"
 docker() { printf 'docker %s\n' "$*"; }
 report_container_failure 'HTTPS intercept smoke' 22 fixture-container "$2"`
	cmd := exec.Command("bash", "-c", script, "test", "../container-diagnostics.sh", dir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("diagnostic helper: %v\n%s", err, output)
	}
	text := string(output)
	for _, want := range []string{"stage=HTTPS intercept smoke status=22", "docker logs --tail 80 fixture-container", "https origin stderr", "actionable fixture failure"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q: %s", want, text)
		}
	}
	if strings.Count(text, "old fixture line") != 79 {
		t.Fatal("fixture diagnostics must retain only the last 80 lines")
	}
}

func TestContainerCurlBoundsRequests(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "curl"), []byte("#!/usr/bin/env bash\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$1"; PATH="$2:$PATH"; container_curl -fsS http://fixture/`, "test", "../container-diagnostics.sh", dir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(output), "--connect-timeout\n2\n--max-time\n15\n") {
		t.Fatalf("probe did not bound connect and total time: %s", output)
	}
}
func TestContainerCurlStalledResponseTimesOut(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer func() { close(release); server.Close() }()
	cmd := exec.Command("bash", "-c", `source "$1"; container_curl --max-time 0.2 -fsS "$2"`, "test", "../container-diagnostics.sh", server.URL)
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 28 {
		t.Fatalf("stalled probe did not hit curl deadline: err=%v output=%s", err, output)
	}
}

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/moby/patternmatcher"
	"github.com/moby/patternmatcher/ignorefile"
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
	if !strings.Contains(stdout.String(), "healthcheck") {
		t.Fatalf("help %q missing healthcheck", stdout.String())
	}
	if strings.Contains(stdout.String(), "Management, TLS intercept") {
		t.Fatalf("help still lists TLS intercept as unbound: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "mcp-stdio") {
		t.Fatalf("help %q missing mcp-stdio", stdout.String())
	}
	if strings.Contains(stdout.String(), "mcp-stdio       Streamable MCP over stdio\n\nPlanned") {
		t.Fatal("help still lists mcp-stdio as planned")
	}
}

func TestMCPStdioRequiresConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labmitm", "mcp-stdio"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--config") {
		t.Fatalf("stderr %q missing --config", stderr.String())
	}
}

func TestMCPStdioRequiresTokenFile(t *testing.T) {
	path := testdataConfig(t, "valid", "defaults.yaml")
	var stdout, stderr bytes.Buffer
	code := run([]string{"labmitm", "mcp-stdio", "--config", path}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d want 2 stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--token-file") {
		t.Fatalf("stderr %q missing --token-file", stderr.String())
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

func TestDebugStatus(t *testing.T) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		t.Skip("/proc/self/status not available")
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"labmitm", "debug-status"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Uid:") {
		t.Fatalf("stdout=%q missing Uid", stdout.String())
	}
	if !strings.Contains(stdout.String(), "CapEff:") {
		t.Fatalf("stdout=%q missing CapEff", stdout.String())
	}
}

func TestDebugStatusSystemCerts(t *testing.T) {
	if _, err := os.Stat("/etc/ssl/certs/ca-certificates.crt"); err != nil {
		t.Skip("system CA bundle not available")
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"labmitm", "debug-status", "--check-system-certs"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "SystemCertPool: non-empty") {
		t.Fatalf("stdout=%q missing SystemCertPool", stdout.String())
	}
}

func TestDockerfileHardening(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"FROM scratch",
		"USER 65532:65532",
		"Apache-2.0",
		"ghcr.io/hilather/labmitm",
		`ENTRYPOINT ["/labmitm"]`,
		`CMD ["serve", "--config=/etc/labmitm/config.yaml", "--management-listen=:8088"]`,
		`CMD ["/labmitm", "healthcheck", "--url=http://127.0.0.1:8088/v1/health/ready"]`,
		"EXPOSE 8888/tcp 8088/tcp",
		"/etc/ssl/certs/ca-certificates.crt",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("Dockerfile missing %q", want)
		}
	}
	if strings.Contains(text, "FROM node") || strings.Contains(text, "node:") {
		t.Error("Dockerfile must not have a Node stage")
	}
	if strings.Contains(text, "node -e") || strings.Contains(text, `CMD ["node"`) {
		t.Error("Dockerfile healthcheck must not exec node")
	}
}

// TestDockerignoreExcludesContext locks the image build context. Patterns
// are applied with github.com/moby/patternmatcher, the matcher BuildKit and
// the Docker CLI use for .dockerignore. Git metadata, workflows, docs, and
// every testdata directory (TLS keys and the container token live under
// testdata) stay out. Built Go sources outside testdata stay in. Tracked
// files under internal/web/dist and internal/web/stub stay in, including
// paths the context walk does not classify as Go sources.
func TestDockerignoreExcludesContext(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, ".dockerignore"))
	if err != nil {
		t.Fatal(err)
	}
	patterns, err := ignorefile.ReadAll(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	pm, err := patternmatcher.New(patterns)
	if err != nil {
		t.Fatal(err)
	}

	assertTrackedUIInDockerContext(t, root, pm)

	for _, rel := range []string{
		".git/config",
		".github/workflows/ci.yml",
		"docs/x.md",
		"testdata/tls/server.key",
		"internal/config/testdata/x",
	} {
		matched, err := pm.MatchesOrParentMatches(rel)
		if err != nil {
			t.Fatalf("match %s: %v", rel, err)
		}
		if !matched {
			t.Errorf(".dockerignore matcher did not exclude %s", rel)
		}
	}
	for _, rel := range []string{
		"go.mod",
		"go.sum",
		"LICENSE",
		"cmd/labmitm/main.go",
		"internal/web/dist/index.html",
		"internal/web/stub/index.html",
		"Dockerfile",
	} {
		matched, err := pm.MatchesOrParentMatches(rel)
		if err != nil {
			t.Fatalf("match %s: %v", rel, err)
		}
		if matched {
			t.Errorf(".dockerignore matcher excluded %s (the image build needs it)", rel)
		}
	}

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.IsDir() && dockerignoreSkipDir(rel) {
			return filepath.SkipDir
		}
		matched, err := pm.MatchesOrParentMatches(rel)
		if err != nil {
			return fmt.Errorf("match %s: %w", rel, err)
		}
		inTestdata := dockerignorePathSegment(rel, "testdata")
		if inTestdata && !matched {
			t.Errorf(".dockerignore matcher did not exclude testdata path %s", rel)
		}
		if !d.IsDir() && strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go") && !inTestdata && matched {
			t.Errorf(".dockerignore matcher excluded built Go file %s", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// assertTrackedUIInDockerContext requires every git-tracked file under the
// embedded UI trees to stay in the build context. It is independent of the
// walk. Skip only when git is not on PATH or rev-parse says this directory
// is not a work tree; any other git error fails the test.
func assertTrackedUIInDockerContext(t *testing.T, root string, pm *patternmatcher.PatternMatcher) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
	probe := exec.Command("git", "-C", root, "rev-parse", "--is-inside-work-tree")
	probe.Dir = root
	probeOut, err := probe.CombinedOutput()
	probeText := strings.TrimSpace(string(probeOut))
	if err != nil {
		if strings.Contains(probeText, "not a git repository") || strings.Contains(probeText, "not a work tree") {
			t.Skip("not a git work tree")
		}
		t.Fatalf("git rev-parse --is-inside-work-tree: %v\n%s", err, probeText)
	}
	if probeText != "true" {
		t.Skip("not a git work tree")
	}

	ls := exec.Command("git", "-C", root, "ls-files", "-z", "--", "internal/web/dist", "internal/web/stub")
	ls.Dir = root
	lsOut, err := ls.Output()
	if err != nil {
		msg := ""
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			msg = string(exitErr.Stderr)
		}
		t.Fatalf("git ls-files -z internal/web/dist internal/web/stub: %v\n%s", err, msg)
	}
	var tracked []string
	for _, b := range bytes.Split(lsOut, []byte{0}) {
		if len(b) == 0 {
			continue
		}
		tracked = append(tracked, filepath.ToSlash(string(b)))
	}
	if len(tracked) == 0 {
		t.Fatal("git ls-files -z internal/web/dist internal/web/stub returned no files")
	}
	var excluded []string
	for _, rel := range tracked {
		matched, matchErr := pm.MatchesOrParentMatches(rel)
		if matchErr != nil {
			t.Fatalf("match %s: %v", rel, matchErr)
		}
		if matched {
			excluded = append(excluded, rel)
		}
	}
	if len(excluded) > 0 {
		t.Errorf(".dockerignore matcher excluded tracked UI files:\n%s", strings.Join(excluded, "\n"))
	}
}

// dockerignoreSkipDir reports directories the context walk does not enter.
// Exact repo-relative paths cover .git, dist, web/dist, and the root bin
// directory. Local caches match any path segment: node_modules, .gocache,
// .gomodcache, and coverage. A basename of dist is not a skip, so
// internal/web/dist is walked.
func dockerignoreSkipDir(rel string) bool {
	switch rel {
	case ".git", "dist", "web/dist", "bin":
		return true
	}
	for _, seg := range strings.Split(rel, "/") {
		switch seg {
		case "node_modules", ".gocache", ".gomodcache", "coverage":
			return true
		}
	}
	return false
}

// dockerignorePathSegment reports whether rel, a slash-separated relative
// path, has a segment equal to name. "under testdata" means a segment
// exactly testdata.
func dockerignorePathSegment(rel, name string) bool {
	for _, seg := range strings.Split(rel, "/") {
		if seg == name {
			return true
		}
	}
	return false
}

func TestComposeSmokeContract(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "examples", "compose.smoke.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		`test: ["CMD", "/labmitm", "healthcheck", "--url=http://127.0.0.1:8088/v1/health/ready"]`,
		`user: "65532:65532"`,
		"read_only: true",
		"cap_drop:",
		"- ALL",
		"tmpfs:",
		"- /tmp",
		"no-new-privileges:true",
		"testdata/container/token",
		"--management-listen=:8088",
		"8888:8888/tcp",
		"8088:8088/tcp",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("compose.smoke.yaml missing %q", want)
		}
	}
	if strings.Contains(text, "node -e") || strings.Contains(text, `"node"`) {
		t.Error("compose smoke healthcheck must not exec node")
	}
	if strings.Contains(text, "serve") && strings.Contains(text, "--token-file") {
		t.Error("compose smoke must not pass serve --token-file")
	}
}

func TestExampleAndContainerYAML(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{
		filepath.Join("testdata", "container", "config.yaml"),
		filepath.Join("examples", "labmitm.yaml"),
	} {
		path := filepath.Join(root, rel)
		if _, err := config.LoadFile(path); err != nil {
			t.Fatalf("load %s: %v", rel, err)
		}
	}
}

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/config"
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
	path := filepath.Join(root, "testdata", "container", "config.yaml")
	if _, err := config.LoadFile(path); err != nil {
		t.Fatalf("load testdata/container/config.yaml: %v", err)
	}
}

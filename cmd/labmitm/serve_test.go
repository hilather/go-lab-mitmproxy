package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/observability"
)

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestServeInvalidDoesNotBind(t *testing.T) {
	path := testdataConfig(t, "invalid", "unknown-field.yaml")
	var stdout, stderr bytes.Buffer
	code := serveCmd(context.Background(), []string{"--config", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit %d want 1 stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "proxy listen=") {
		t.Fatalf("invalid bootstrap bound proxy: %q", stdout.String())
	}
}

func TestServeBindsProxyManagementOff(t *testing.T) {
	origin := httptestOrigin(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr safeBuffer
	pid := filepath.Join(t.TempDir(), "labmitm.pid")
	done := make(chan int, 1)
	go func() {
		done <- serveCmd(ctx, []string{
			"--config", writeServeConfig(t, "", false, false),
			"--proxy-listen", "127.0.0.1:0",
			"--management-listen", "off",
			"--pid-file", pid,
		}, &stdout, &stderr)
	}()
	addr := waitProxyListen(t, &stdout)
	body := getViaProxy(t, addr, origin+"/")
	if body != "origin" {
		t.Fatalf("body %q stderr=%q", body, stderr.String())
	}
	raw, err := os.ReadFile(pid)
	if err != nil {
		t.Fatalf("pid-file: %v", err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		t.Fatal("empty pid file")
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit %d stderr=%q", code, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not exit")
	}
}

func TestServeManagementListenRequiresToken(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := serveCmd(context.Background(), []string{
		"--config", testdataConfig(t, "valid", "defaults.yaml"),
		"--proxy-listen", "127.0.0.1:0",
		"--management-listen", "127.0.0.1:0",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit %d want 1 stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "token") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestServeManagementBindsWithToken(t *testing.T) {
	cfg := writeTokenConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr safeBuffer
	done := make(chan int, 1)
	go func() {
		done <- serveCmd(ctx, []string{
			"--config", cfg,
			"--proxy-listen", "127.0.0.1:0",
			"--management-listen", "127.0.0.1:0",
		}, &stdout, &stderr)
	}()
	mgmt := waitPrefix(t, &stdout, "labmitm management listen=")
	unauth := waitHTTP(t, "http://"+mgmt+"/v1/flows", "")
	_ = unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth status=%d", unauth.StatusCode)
	}
	resp := waitHTTP(t, "http://"+mgmt+"/v1/ca", serveTestToken)
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ca status=%d body=%s", resp.StatusCode, b)
	}
	if strings.Contains(string(b), "PRIVATE KEY") {
		t.Fatal("GET /v1/ca leaked a private key")
	}
	live := waitHTTP(t, "http://"+mgmt+"/v1/health/live", "")
	_ = live.Body.Close()
	if live.StatusCode != http.StatusOK {
		t.Fatalf("live status=%d", live.StatusCode)
	}
	pingBody := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"serve-test","version":"dev"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
	mcpReq, err := http.NewRequest(http.MethodPost, "http://"+mgmt+"/mcp", strings.NewReader(pingBody))
	if err != nil {
		t.Fatal(err)
	}
	mcpReq.Header.Set("Content-Type", "application/json")
	mcpReq.Header.Set("Accept", "application/json, text/event-stream")
	mcpReq.Header.Set("MCP-Protocol-Version", "2026-07-28")
	mcpReq.Header.Set("Mcp-Method", "server/discover")
	mcpReq.Header.Set("Authorization", "Bearer "+serveTestToken)
	mcpResp, err := http.DefaultClient.Do(mcpReq)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	mcpBody, _ := io.ReadAll(mcpResp.Body)
	_ = mcpResp.Body.Close()
	if mcpResp.StatusCode == http.StatusNotFound || mcpResp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("POST /mcp not mounted or unauth status=%d body=%s", mcpResp.StatusCode, mcpBody)
	}
	if mcpResp.StatusCode != http.StatusOK && mcpResp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /mcp status=%d body=%s", mcpResp.StatusCode, mcpBody)
	}
	ready := waitHTTP(t, "http://"+mgmt+"/v1/health/ready", "")
	_ = ready.Body.Close()
	if ready.StatusCode != http.StatusOK {
		t.Fatalf("ready status=%d", ready.StatusCode)
	}
	var hcOut, hcErr bytes.Buffer
	if code := healthcheckCmd([]string{"--url", "http://" + mgmt + "/v1/health/ready"}, &hcOut, &hcErr); code != 0 {
		t.Fatalf("healthcheck exit %d stderr=%q", code, hcErr.String())
	}
	hidden := waitHTTP(t, "http://"+mgmt+"/v1/metrics", serveTestToken)
	_ = hidden.Body.Close()
	if hidden.StatusCode != http.StatusNotFound {
		t.Fatalf("publicPath false: metrics status=%d", hidden.StatusCode)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit %d stderr=%q", code, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not exit")
	}
}

const serveTestToken = "0123456789abcdef0123456789abcdef"

func writeTokenConfig(t *testing.T) string {
	t.Helper()
	return writeServeConfig(t, "", false, true)
}

func writeServeConfig(t *testing.T, metricsListen string, publicPath, withToken bool) string {
	t.Helper()
	dir := t.TempDir()
	var authBlock string
	if withToken {
		tok := filepath.Join(dir, "admin.token")
		if err := os.WriteFile(tok, []byte(serveTestToken+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		authBlock = "  management:\n    auth:\n      mode: bearer\n      tokens:\n        - id: admin\n          secretFile: " + tok + "\n          role: administrator\n"
	}
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: lab-proxy\nspec:\n" + authBlock +
		"  observability:\n    metrics:\n      listen: \"" + metricsListen + "\"\n      publicPath: " + strconv.FormatBool(publicPath) + "\n"
	path := filepath.Join(dir, "labmitm.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func waitHTTP(t *testing.T, rawURL, token string) *http.Response {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			return resp
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("http %s: %v", rawURL, last)
	return nil
}

func waitPrefix(t *testing.T, stdout *safeBuffer, prefix string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s := stdout.String()
		if i := strings.Index(s, prefix); i >= 0 {
			rest := s[i+len(prefix):]
			return strings.TrimSpace(strings.Split(rest, "\n")[0])
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %q, stdout=%q", prefix, stdout.String())
	return ""
}

func waitProxyListen(t *testing.T, stdout *safeBuffer) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s := stdout.String()
		const p = "proxy listen="
		if i := strings.Index(s, p); i >= 0 {
			rest := s[i+len(p):]
			return strings.TrimSpace(strings.Split(rest, "\n")[0])
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for listen, stdout=%q", stdout.String())
	return ""
}

func TestServeMetricsListenAndPublicPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// YAML rejects port 0 (1–65535). Empty listen disables the scrape
	// listener; publicPath still serves authenticated GET /v1/metrics.
	path := writeServeConfig(t, "", true, true)
	var stdout, stderr safeBuffer
	done := make(chan int, 1)
	go func() {
		done <- serveCmd(ctx, []string{
			"--config", path,
			"--proxy-listen", "127.0.0.1:0",
			"--management-listen", "127.0.0.1:0",
		}, &stdout, &stderr)
	}()
	mgmt := waitPrefix(t, &stdout, "labmitm management listen=")
	if strings.Contains(stdout.String(), "labmitm metrics listen=") {
		t.Fatalf("empty metrics.listen must not bind scrape: %q", stdout.String())
	}

	unauth := waitHTTP(t, "http://"+mgmt+"/v1/metrics", "")
	_ = unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated metrics status=%d want 401", unauth.StatusCode)
	}
	pub := waitHTTP(t, "http://"+mgmt+"/v1/metrics", serveTestToken)
	defer func() { _ = pub.Body.Close() }()
	if pub.StatusCode != 200 {
		t.Fatalf("publicPath true: status=%d stderr=%q", pub.StatusCode, stderr.String())
	}
	if !strings.Contains(pub.Header.Get("Content-Type"), "openmetrics") {
		t.Fatalf("content-type=%s", pub.Header.Get("Content-Type"))
	}
	body, _ := io.ReadAll(pub.Body)
	if !strings.Contains(string(body), "# EOF") {
		t.Fatalf("body=%s", body)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit %d stderr=%q", code, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not exit")
	}
}

func TestServeReadyGoesUnreadyOnProxyShutdown(t *testing.T) {
	rt, err := serveFromConfig(context.Background(), serveFlags{
		Config:           writeServeConfig(t, "", false, true),
		ProxyListen:      "127.0.0.1:0",
		ManagementListen: "127.0.0.1:0",
		ShutdownTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = rt.shutdown(ctx)
	})
	mgmt := rt.http.Addr()
	ready := waitHTTP(t, "http://"+mgmt+"/v1/health/ready", "")
	_ = ready.Body.Close()
	if ready.StatusCode != http.StatusOK {
		t.Fatalf("ready before shutdown status=%d", ready.StatusCode)
	}
	shctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rt.proxy.Shutdown(shctx); err != nil {
		t.Fatal(err)
	}
	unready := waitHTTP(t, "http://"+mgmt+"/v1/health/ready", "")
	_ = unready.Body.Close()
	if unready.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("ready after proxy shutdown status=%d want 503", unready.StatusCode)
	}
}

func TestServeOrigDestOffFollowsLiveSpec(t *testing.T) {
	path := writeServeConfig(t, "", false, true)
	rt, err := serveFromConfig(context.Background(), serveFlags{
		Config:           path,
		ProxyListen:      "127.0.0.1:0",
		ManagementListen: "off",
		ShutdownTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = rt.shutdown(ctx)
	})
	before := rt.svc.HealthFacts()
	if !before.OrigDestOff || before.OrigDestBound {
		t.Fatalf("boot facts=%+v", before)
	}
	if !observability.Evaluate(before).Ready {
		t.Fatalf("disabled orig-dest must be ready: %+v", before)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	enabled := strings.Replace(string(raw), "spec:\n",
		"spec:\n  listeners:\n    originalDestination:\n      enabled: true\n", 1)
	if enabled == string(raw) {
		t.Fatal("could not inject originalDestination.enabled")
	}
	if err := os.WriteFile(path, []byte(enabled), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.svc.Reset(context.Background(), app.Actor{ID: "test", Class: "test", Transport: "direct"}, app.ResetIn{Reason: "enable orig-dest"}); err != nil {
		t.Fatal(err)
	}
	after := rt.svc.HealthFacts()
	if after.OrigDestOff {
		t.Fatalf("Reset-to-enable must not keep OrigDestOff: %+v", after)
	}
	if after.OrigDestBound {
		t.Fatal("Reset must not rebind orig-dest")
	}
	if observability.Evaluate(after).Ready {
		t.Fatalf("enabled unbound must be unready: %+v", after)
	}
}

func httptestOrigin(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "origin")
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return "http://" + ln.Addr().String()
}

func getViaProxy(t *testing.T, proxyAddr, target string) string {
	t.Helper()
	tr := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return &url.URL{Scheme: "http", Host: proxyAddr}, nil
		},
		ForceAttemptHTTP2: false,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %q", resp.StatusCode, b)
	}
	return string(b)
}

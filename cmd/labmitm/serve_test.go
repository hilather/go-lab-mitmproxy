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
	"strings"
	"sync"
	"testing"
	"time"
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
			"--config", testdataConfig(t, "valid", "defaults.yaml"),
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
	dir := t.TempDir()
	tok := filepath.Join(dir, "admin.token")
	if err := os.WriteFile(tok, []byte(serveTestToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: lab-proxy\nspec:\n  management:\n    auth:\n      mode: bearer\n      tokens:\n        - id: admin\n          secretFile: " + tok + "\n          role: administrator\n"
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

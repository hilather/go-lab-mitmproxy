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

func TestServeManagementListenRejected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := serveCmd(context.Background(), []string{
		"--config", testdataConfig(t, "valid", "defaults.yaml"),
		"--proxy-listen", "127.0.0.1:0",
		"--management-listen", "127.0.0.1:0",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit %d want 1 stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "proxy listen=") {
		t.Fatalf("management request bound proxy: %q", stdout.String())
	}
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

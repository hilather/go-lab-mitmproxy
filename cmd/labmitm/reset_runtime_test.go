package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func freeAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}
func runtimeConfig(t *testing.T, path, proxyAddr, mgmtAddr, metricsAddr, tlsBlock string) {
	t.Helper()
	if path == "" {
		t.Fatal("empty config path")
	}
	token := filepath.Join(filepath.Dir(path), "token")
	if err := os.WriteFile(token, []byte(serveTestToken), 0600); err != nil {
		t.Fatal(err)
	}
	doc := fmt.Sprintf(`apiVersion: labmitm.dev/v1alpha1
kind: LabMITM
metadata:
  name: runtime-test
spec:
  listeners:
    proxy:
      address: %q
    management:
      address: %q
%s
  management:
    auth:
      mode: bearer
      tokens:
        - id: admin
          secretFile: %q
          role: administrator
  observability:
    metrics:
      listen: %q
`, proxyAddr, mgmtAddr, tlsBlock, token, metricsAddr)
	if err := os.WriteFile(path, []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
}
func startTestRuntime(t *testing.T, path, management string) *serveRuntime {
	t.Helper()
	rt, err := serveFromConfig(context.Background(), serveFlags{Config: path, ManagementListen: management})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = rt.shutdown(ctx)
	})
	return rt
}
func assertPortClosed(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("retired listener remains open: %s", addr)
	}
}
func tlsBlock(t *testing.T) string {
	t.Helper()
	cert, err := filepath.Abs("../../testdata/tls/origin.pem")
	if err != nil {
		t.Fatal(err)
	}
	key, err := filepath.Abs("../../testdata/tls/origin-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("      tls:\n        enabled: true\n        certFile: %q\n        keyFile: %q", cert, key)
}
func tlsHTTP(t *testing.T, addr string) {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	resp, err := client.Get("https://" + addr + "/v1/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("TLS ready status %d", resp.StatusCode)
	}
	plain := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: time.Second}
	resp, err = plain.Get("http://" + addr + "/v1/health/live")
	if err == nil {
		defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)
		if resp.StatusCode == 200 {
			t.Fatal("management TLS accepted plaintext HTTP")
		}
	}
}
func TestManagementTLSActuallyServesTLS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	runtimeConfig(t, path, freeAddress(t), freeAddress(t), "", tlsBlock(t))
	rt := startTestRuntime(t, path, "")
	tlsHTTP(t, rt.http.Addr())
}
func TestResetRebindsListenersAndCompletesManagementResponse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	oldProxy, oldMgmt, oldMetrics := freeAddress(t), freeAddress(t), freeAddress(t)
	runtimeConfig(t, path, oldProxy, oldMgmt, oldMetrics, "")
	rt := startTestRuntime(t, path, "")
	if _, err := rt.svc.Inbox().Insert(context.Background(), rt.svc.Inbox().Epoch(), &model.Flow{ID: "before-reset"}); err != nil {
		t.Fatal(err)
	}
	newProxy, newMgmt, newMetrics := freeAddress(t), freeAddress(t), freeAddress(t)
	runtimeConfig(t, path, newProxy, newMgmt, newMetrics, tlsBlock(t))
	req, err := http.NewRequest("POST", "http://"+oldMgmt+"/v1/state:reset", strings.NewReader(`{"reason":"rebind"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+serveTestToken)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("reset status %d: %s", resp.StatusCode, body)
	}
	for _, addr := range []string{oldProxy, oldMgmt, oldMetrics} {
		assertPortClosed(t, addr)
	}
	if rt.proxy.Addr().String() != newProxy || rt.http.Addr() != newMgmt || rt.metrics.Addr() != newMetrics {
		t.Fatal("new listener addresses were not published")
	}
	conn, err := net.DialTimeout("tcp", newProxy, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	tlsHTTP(t, newMgmt)
	metrics, err := client.Get("http://" + newMetrics + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	_ = metrics.Body.Close()
	if metrics.StatusCode != 200 {
		t.Fatal(metrics.StatusCode)
	}
	if rt.svc.Inbox().Stats().FlowCount != 0 {
		t.Fatal("successful reset did not wipe flows")
	}
	origin := httptestOrigin(t)
	if body := getViaProxy(t, newProxy, origin+"/"); body != "origin" {
		t.Fatalf("rebound proxy did not forward: %q", body)
	}
}
func TestResetListenerFailuresPreserveStateFlowsAndBindings(t *testing.T) {
	for _, failure := range []string{"proxy", "management", "metrics", "tls"} {
		t.Run(failure, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			oldProxy, oldMgmt, oldMetrics := freeAddress(t), freeAddress(t), freeAddress(t)
			runtimeConfig(t, path, oldProxy, oldMgmt, oldMetrics, "")
			rt := startTestRuntime(t, path, "")
			before := rt.svc.Active()
			epoch := rt.svc.Inbox().Epoch()
			if _, err := rt.svc.Inbox().Insert(context.Background(), rt.svc.Inbox().Epoch(), &model.Flow{ID: "preserved"}); err != nil {
				t.Fatal(err)
			}
			occupied, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = occupied.Close() }()
			proxyAddr, mgmtAddr, metricsAddr := freeAddress(t), freeAddress(t), freeAddress(t)
			block := ""
			switch failure {
			case "proxy":
				proxyAddr = occupied.Addr().String()
			case "management":
				mgmtAddr = occupied.Addr().String()
			case "metrics":
				metricsAddr = occupied.Addr().String()
			case "tls":
				block = "      tls:\n        enabled: true\n        certFile: /missing-cert\n        keyFile: /missing-key"
			}
			runtimeConfig(t, path, proxyAddr, mgmtAddr, metricsAddr, block)
			_, err = rt.svc.Reset(context.Background(), app.Actor{ID: "test"}, app.ResetIn{Reason: "fail"})
			if err == nil {
				t.Fatal("reset unexpectedly succeeded")
			}
			if failure != "tls" {
				de, ok := domainerr.As(err)
				if !ok || de.Code != domainerr.CodeValidationFailed || de.Retryable || de.Remediation == "" {
					t.Fatalf("occupied address must return nonretryable validation with remediation: %v", err)
				}
			}
			if rt.svc.Active() != before || rt.svc.Inbox().Epoch() != epoch || rt.svc.Inbox().Stats().FlowCount != 1 {
				t.Fatal("failed Reset changed state or flows")
			}
			for _, addr := range []string{oldProxy, oldMgmt, oldMetrics} {
				conn, err := net.DialTimeout("tcp", addr, time.Second)
				if err != nil {
					t.Fatalf("old bind lost: %s: %v", addr, err)
				}
				_ = conn.Close()
			}
			for _, addr := range []string{proxyAddr, mgmtAddr, metricsAddr} {
				if addr != occupied.Addr().String() {
					assertPortClosed(t, addr)
				}
			}
		})
	}
}

func TestResetOverlappingListenerAddressReturnsValidationAndRollsBack(t *testing.T) {
	for _, listener := range []string{"proxy", "management", "metrics"} {
		t.Run(listener, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			oldProxy, oldMgmt, oldMetrics := freeAddress(t), freeAddress(t), freeAddress(t)
			runtimeConfig(t, path, oldProxy, oldMgmt, oldMetrics, "")
			rt := startTestRuntime(t, path, "")
			before := rt.svc.Active()
			epoch := rt.svc.Inbox().Epoch()
			inserted, err := rt.svc.Inbox().Insert(context.Background(), epoch, &model.Flow{Host: "preserved.lab"})
			if err != nil {
				t.Fatal(err)
			}
			oldAddress := map[string]string{"proxy": oldProxy, "management": oldMgmt, "metrics": oldMetrics}[listener]
			_, port, err := net.SplitHostPort(oldAddress)
			if err != nil {
				t.Fatal(err)
			}
			overlap := net.JoinHostPort("0.0.0.0", port)
			proxyAddr, mgmtAddr, metricsAddr := freeAddress(t), freeAddress(t), freeAddress(t)
			switch listener {
			case "proxy":
				proxyAddr = overlap
			case "management":
				mgmtAddr = overlap
			case "metrics":
				metricsAddr = overlap
			}
			runtimeConfig(t, path, proxyAddr, mgmtAddr, metricsAddr, "")
			req, err := http.NewRequest("POST", "http://"+oldMgmt+"/v1/state:reset", strings.NewReader(`{"reason":"overlapping bind"}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+serveTestToken)
			req.Header.Set("Content-Type", "application/json")
			transport := &http.Transport{DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			var problem capabilities.Problem
			if err := json.Unmarshal(body, &problem); err != nil {
				t.Fatalf("decode problem %q: %v", body, err)
			}
			if resp.StatusCode != http.StatusBadRequest || problem.Code != domainerr.CodeValidationFailed || problem.Retryable {
				t.Errorf("overlapping Reset must return nonretryable validation: HTTP %d: %s", resp.StatusCode, body)
			}
			if !strings.Contains(problem.Detail, overlap) || !strings.Contains(problem.Remediation, "restart") || !strings.Contains(problem.Remediation, "intermediate port") {
				t.Errorf("overlapping Reset must name address and remediation: %s", body)
			}
			if rt.svc.Active() != before || rt.svc.Inbox().Epoch() != epoch || rt.svc.Inbox().Stats().FlowCount != 1 {
				t.Fatal("failed Reset changed state or flows")
			}
			if _, err := rt.svc.Inbox().Get(inserted.ID); err != nil {
				t.Fatalf("failed Reset lost preserved flow: %v", err)
			}
			if rt.proxy.Addr().String() != oldProxy || rt.http.Addr() != oldMgmt || rt.metrics.Addr() != oldMetrics {
				t.Fatal("failed Reset published staged listener addresses")
			}
			for _, addr := range []string{oldProxy, oldMgmt, oldMetrics} {
				conn, err := net.DialTimeout("tcp", addr, time.Second)
				if err != nil {
					t.Fatalf("old bind lost: %s: %v", addr, err)
				}
				_ = conn.Close()
			}
			for _, addr := range []string{proxyAddr, mgmtAddr, metricsAddr} {
				if addr == overlap {
					continue
				}
				ln, err := net.Listen("tcp", addr)
				if err != nil {
					t.Fatalf("staged address was not released: %s: %v", addr, err)
				}
				_ = ln.Close()
			}
			if body := getViaProxy(t, oldProxy, httptestOrigin(t)+"/"); body != "origin" {
				t.Fatalf("old proxy no longer forwards after failed Reset: %q", body)
			}
		})
	}
}

func TestResetSameManagementAddressChangesTLSAndKeepsManagementOff(t *testing.T) {
	for _, off := range []bool{false, true} {
		t.Run(fmt.Sprint(off), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			proxyAddr, mgmtAddr := freeAddress(t), freeAddress(t)
			runtimeConfig(t, path, proxyAddr, mgmtAddr, "", "")
			flag := ""
			if off {
				flag = "off"
			}
			rt := startTestRuntime(t, path, flag)
			runtimeConfig(t, path, proxyAddr, mgmtAddr, "", tlsBlock(t))
			if _, err := rt.svc.Reset(context.Background(), app.Actor{ID: "test"}, app.ResetIn{Reason: "TLS"}); err != nil {
				t.Fatal(err)
			}
			if off {
				assertPortClosed(t, mgmtAddr)
				if !rt.svc.HealthFacts().MgmtOff {
					t.Fatal("management-off override lost")
				}
			} else {
				tlsHTTP(t, mgmtAddr)
			}
		})
	}
}

func TestInvalidManagementTLSFailsBeforeBindingProxy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	proxyAddr, mgmtAddr := freeAddress(t), freeAddress(t)
	runtimeConfig(t, path, proxyAddr, mgmtAddr, "", "      tls:\n        enabled: true\n        certFile: /missing-cert\n        keyFile: /missing-key")
	if rt, err := serveFromConfig(context.Background(), serveFlags{Config: path, ManagementListen: ""}); err == nil {
		_ = rt.shutdown(context.Background())
		t.Fatal("invalid management TLS started runtime")
	}
	assertPortClosed(t, proxyAddr)
	assertPortClosed(t, mgmtAddr)
}

func TestResetReconcilesOriginalDestinationWithRollback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("original destination requires Linux")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	proxyAddr := freeAddress(t)
	mgmtAddr := freeAddress(t)
	rewrite := func(enabled bool, addr string) {
		runtimeConfig(t, path, proxyAddr, mgmtAddr, "", "")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		doc := strings.Replace(string(raw), "    management:\n", fmt.Sprintf("    originalDestination:\n      enabled: %t\n      address: %q\n    management:\n", enabled, addr), 1)
		if err := os.WriteFile(path, []byte(doc), 0600); err != nil {
			t.Fatal(err)
		}
	}
	rewrite(false, "")
	rt := startTestRuntime(t, path, "off")
	apply := func() error {
		_, err := rt.svc.Reset(context.Background(), app.Actor{ID: "test"}, app.ResetIn{Reason: "original destination"})
		return err
	}
	first := freeAddress(t)
	rewrite(true, first)
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	if rt.proxy.OrigDestAddr().String() != first || !rt.svc.HealthFacts().OrigDestBound {
		t.Fatal("Reset did not bind orig-dest")
	}
	second := freeAddress(t)
	rewrite(true, second)
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	assertPortClosed(t, first)
	conn, err := net.DialTimeout("tcp", second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	before := rt.svc.Active()
	epoch := rt.svc.Inbox().Epoch()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = occupied.Close() }()
	oldProxy := proxyAddr
	stagedProxy := freeAddress(t)
	proxyAddr = stagedProxy
	rewrite(true, occupied.Addr().String())
	if err := apply(); err == nil {
		t.Fatal("orig-dest bind failure succeeded")
	}
	if rt.svc.Active() != before || rt.svc.Inbox().Epoch() != epoch || rt.proxy.OrigDestAddr().String() != second {
		t.Fatal("failed original destination Reset changed runtime")
	}
	assertPortClosed(t, stagedProxy)
	if rt.proxy.Addr().String() != oldProxy {
		t.Fatal("failed orig-dest preparation published staged proxy bind")
	}
	proxyAddr = oldProxy
	rewrite(false, "")
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	assertPortClosed(t, second)
	if rt.proxy.OrigDestAddr() != nil || !rt.svc.HealthFacts().OrigDestOff {
		t.Fatal("Reset did not disable orig-dest")
	}
}

func TestResetKeepsInFlightProxyRequestAndCLIOverride(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(fmt.Sprint(override), func(t *testing.T) {
			entered, released := make(chan struct{}), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(released) }) }
			defer release()
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-released
				_, _ = io.WriteString(w, "in-flight")
			}))
			defer func() { release(); origin.Close() }()
			path := filepath.Join(t.TempDir(), "config.yaml")
			configuredProxy := freeAddress(t)
			runtimeConfig(t, path, configuredProxy, freeAddress(t), "", "")
			flags := serveFlags{Config: path, ManagementListen: "off"}
			if override {
				flags.ProxyListen = "127.0.0.1:0"
			}
			rt, err := serveFromConfig(context.Background(), flags)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = rt.shutdown(ctx)
			}()
			old := rt.proxy.Addr().String()
			proxyURL, _ := url.Parse("http://" + old)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
			done := make(chan error, 1)
			go func() {
				resp, err := client.Get(origin.URL)
				if err == nil {
					body, readErr := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					err = readErr
					if string(body) != "in-flight" {
						err = fmt.Errorf("unexpected in-flight response %q", body)
					}
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("request never reached origin")
			}
			next := freeAddress(t)
			runtimeConfig(t, path, next, freeAddress(t), "", "")
			if _, err := rt.svc.Reset(context.Background(), app.Actor{ID: "test"}, app.ResetIn{Reason: "in-flight"}); err != nil {
				t.Fatal(err)
			}
			release()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if rt.svc.Inbox().Stats().FlowCount != 0 {
				t.Fatal("in-flight old epoch refilled reset store")
			}
			if override {
				if rt.proxy.Addr().String() != old {
					t.Fatal("Reset lost CLI proxy override")
				}
				assertPortClosed(t, next)
			} else {
				assertPortClosed(t, old)
				if rt.proxy.Addr().String() != next {
					t.Fatal("Reset did not move proxy bind")
				}
			}
		})
	}
}

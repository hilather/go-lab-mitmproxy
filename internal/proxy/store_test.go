package proxy

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
	"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm"
)

func TestStoreInsertCompletedFlow(t *testing.T) {
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "stored")
	}))
	px := startProxy(t, Options{Sink: AdaptStore(inbox)})
	if via := throughProxy(t, px.Addr().String(), originURL+"/cap"); via != "stored" {
		t.Fatalf("body %q", via)
	}
	got := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/cap"})
	if got.Method != http.MethodGet || got.Status != http.StatusOK || string(got.Response.Body) != "stored" {
		t.Fatalf("flow %+v", got)
	}
	if _, err := ulid.Parse(got.ID); err != nil {
		t.Fatalf("id %q: %v", got.ID, err)
	}
}

func TestStoreFullStillForwards(t *testing.T) {
	inbox := newProxyStore(t, store.Options{MaxFlows: 1, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok-"+r.URL.Path)
	}))
	px := startProxy(t, Options{Sink: AdaptStore(inbox)})
	if via := throughProxy(t, px.Addr().String(), originURL+"/one"); via != "ok-/one" {
		t.Fatalf("first %q", via)
	}
	if via := throughProxy(t, px.Addr().String(), originURL+"/two"); via != "ok-/two" {
		t.Fatalf("second (store full) must still forward: %q", via)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && px.Metrics().StoreFull() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	if inbox.Stats().FlowCount != 1 {
		t.Fatalf("count=%d", inbox.Stats().FlowCount)
	}
	if px.Metrics().StoreFull() < 1 {
		t.Fatal("expected store-full metric")
	}
}

func TestStoreRecordsTLSInfoOnIntercept(t *testing.T) {
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "secret-body")
	}))
	_, port := hostPort(t, origin)
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Resolver: appLabResolver()})
	auth := px.Authority()
	if auth == nil {
		t.Fatal("missing lab CA")
	}
	resp, err := httpsViaProxy(t, px.Addr().String(), strconv.Itoa(port), "/hello", auth.CertPool())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "secret-body" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	got := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/hello"})
	if !got.Intercepted || got.TLS == nil || got.TLS.ALPN != tlsmitm.ALPN {
		t.Fatalf("tls %+v intercepted=%v", got.TLS, got.Intercepted)
	}
	if !got.TLS.UpstreamVerified {
		t.Fatal("expected upstream verified")
	}
	if !strings.Contains(got.URL, "/hello") {
		t.Fatalf("url %q", got.URL)
	}
}

func waitFlow(t *testing.T, inbox *store.Memory, filter model.FlowFilter) *model.Flow {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, err := inbox.Wait(ctx, filter)
	if err != nil {
		t.Fatalf("wait store: %v", err)
	}
	return got
}

func newProxyStore(t *testing.T, opts store.Options) *store.Memory {
	t.Helper()
	s, err := store.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Wipe)
	return s
}

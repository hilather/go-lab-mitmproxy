package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

func TestReplayHTTP(t *testing.T) {
	inbox, err := store.New(store.Options{MaxFlows: 10, MaxBytes: 1 << 20, MaxBodyBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inbox.Wipe)
	var sawMethod, sawPath, sawBody string
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMethod = r.Method
		sawPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		sawBody = string(b)
		w.Header().Set("X-Origin", "1")
		_, _ = io.WriteString(w, "replayed")
	}))
	px := startProxy(t, Options{Store: inbox, Sink: AdaptStore(inbox)})
	u := mustURL(t, originURL+"/from-store")
	f, err := px.Replay(context.Background(), &model.Flow{
		Method:   http.MethodPost,
		URL:      originURL + "/from-store",
		Host:     u.Host,
		Scheme:   "http",
		Protocol: model.FlowProtocolHTTP11,
		Request:  model.HTTPMessage{Body: []byte("payload"), Headers: []model.Header{{Name: "Content-Type", Value: "text/plain"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sawMethod != http.MethodPost || sawPath != "/from-store" || sawBody != "payload" {
		t.Fatalf("origin method=%s path=%s body=%q", sawMethod, sawPath, sawBody)
	}
	if f == nil || f.ID == "" || f.Status != 200 || string(f.Response.Body) != "replayed" {
		t.Fatalf("replay flow %+v", f)
	}
	if f.ID == "" {
		t.Fatal("replay must assign a new flow id")
	}
}

func TestReplayIgnoresHTTPProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "direct")
	}))
	px := startProxy(t, Options{})
	u := mustURL(t, originURL)
	f, err := px.Replay(context.Background(), &model.Flow{
		Method:   http.MethodGet,
		URL:      originURL + "/",
		Host:     u.Host,
		Scheme:   "http",
		Protocol: model.FlowProtocolHTTP11,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Response.Body) != "direct" {
		t.Fatalf("HTTP_PROXY was honored: body=%q", f.Response.Body)
	}
}

func TestReplayHairpinRejected(t *testing.T) {
	px := startProxy(t, Options{})
	addr := px.Addr().String()
	_, err := px.Replay(context.Background(), &model.Flow{
		Method:   http.MethodGet,
		URL:      "http://" + addr + "/",
		Host:     addr,
		Scheme:   "http",
		Protocol: model.FlowProtocolHTTP11,
	})
	if err == nil {
		t.Fatal("hairpin must be rejected")
	}
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeTargetDenied {
		t.Fatalf("err=%v", err)
	}
}

func TestReplayRejectsWebsocketAndTruncated(t *testing.T) {
	px := startProxy(t, Options{})
	_, err := px.Replay(context.Background(), &model.Flow{
		Method: http.MethodGet, Host: "127.0.0.1:9", Scheme: "http", Protocol: model.FlowProtocolWebSocket,
	})
	requireReplayCode(t, err, domainerr.CodeValidationFailed)
	_, err = px.Replay(context.Background(), &model.Flow{
		Method: http.MethodConnect, Host: "127.0.0.1:9", Scheme: "http", Protocol: model.FlowProtocolConnect,
	})
	requireReplayCode(t, err, domainerr.CodeValidationFailed)
	_, err = px.Replay(context.Background(), &model.Flow{
		Method: http.MethodGet, Host: "127.0.0.1:9", Scheme: "http", Protocol: model.FlowProtocolHTTP11,
		Request: model.HTTPMessage{Truncated: true},
	})
	requireReplayCode(t, err, domainerr.CodeValidationFailed)
}

func TestReplayHTTPSInterceptOff(t *testing.T) {
	cert := originCert(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "https-off")
	})
	addr := startTLSOrigin(t, cert, mux)
	spec := loadSpec(t)
	spec.TLS.Intercept = false
	spec.TLS.Upstream.InsecureSkipVerify = true
	px := startProxy(t, Options{Spec: spec})
	f, err := px.Replay(context.Background(), &model.Flow{
		Method:   http.MethodGet,
		URL:      "https://" + addr + "/",
		Host:     addr,
		Scheme:   "https",
		Protocol: model.FlowProtocolHTTP11,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Response.Body) != "https-off" {
		t.Fatalf("body=%q", f.Response.Body)
	}
}

func TestReplayHTTPSInterceptOn(t *testing.T) {
	cert := originCert(t)
	pem, err := os.ReadFile(testdataTLS(t, "origin.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("origin pem")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "https-on")
	})
	addr := startTLSOrigin(t, cert, mux)
	spec := loadSpec(t)
	spec.TLS.Intercept = true
	spec.TLS.Upstream.InsecureSkipVerify = true
	px := startProxy(t, Options{Spec: spec})
	f, err := px.Replay(context.Background(), &model.Flow{
		Method:   http.MethodGet,
		URL:      "https://" + addr + "/",
		Host:     addr,
		Scheme:   "https",
		Protocol: model.FlowProtocolHTTP11,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Response.Body) != "https-on" {
		t.Fatalf("body=%q err=%v tls=%v", f.Response.Body, f.Error, px.Authority() != nil)
	}
	_ = tls.Certificate{}
}

func requireReplayCode(t *testing.T, err error, code domainerr.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s", code)
	}
	de, ok := domainerr.As(err)
	if !ok || de.Code != code {
		t.Fatalf("err=%v want %s", err, code)
	}
}

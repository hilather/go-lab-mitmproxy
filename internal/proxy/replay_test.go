package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
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

func TestReplayHairpinWildcardSpec(t *testing.T) {
	for _, listen := range []string{":8888", "0.0.0.0:8888", "[::]:8888"} {
		spec := loadSpec(t)
		spec.Listeners.Proxy.Address = listen
		px := startProxy(t, Options{Address: "127.0.0.1:0", Spec: spec})
		_, err := px.Replay(context.Background(), &model.Flow{
			Method:   http.MethodGet,
			URL:      "http://127.0.0.1:8888/",
			Host:     "127.0.0.1:8888",
			Scheme:   "http",
			Protocol: model.FlowProtocolHTTP11,
		})
		if err == nil {
			t.Fatalf("wildcard spec %q must hairpin 127.0.0.1:8888", listen)
		}
		de, ok := domainerr.As(err)
		if !ok || de.Code != domainerr.CodeTargetDenied {
			t.Fatalf("spec %q err=%v", listen, err)
		}
	}
}

func TestReplayHairpinWildcardBind(t *testing.T) {
	px := startProxy(t, Options{Address: "0.0.0.0:0"})
	_, port, err := net.SplitHostPort(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	host := net.JoinHostPort("127.0.0.1", port)
	_, err = px.Replay(context.Background(), &model.Flow{
		Method:   http.MethodGet,
		URL:      "http://" + host + "/",
		Host:     host,
		Scheme:   "http",
		Protocol: model.FlowProtocolHTTP11,
	})
	if err == nil {
		t.Fatal("0.0.0.0 bind must hairpin 127.0.0.1 on the same port")
	}
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeTargetDenied {
		t.Fatalf("err=%v", err)
	}
}

func TestSameEndpointWildcard(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b string
		want bool
	}{
		{":8888", "127.0.0.1:8888", true},
		{"0.0.0.0:8888", "127.0.0.1:8888", true},
		{"[::]:8888", "127.0.0.1:8888", true},
		{":8888", "[::1]:8888", true},
		{"127.0.0.1:8888", "127.0.0.1:8888", true},
		{"127.0.0.1:8888", "127.0.0.1:9999", false},
		{":8888", "8.8.8.8:8888", false},
		{"0.0.0.0:8888", "8.8.8.8:8888", false},
	}
	for _, tc := range cases {
		if got := sameEndpoint(tc.a, tc.b); got != tc.want {
			t.Errorf("sameEndpoint(%q,%q)=%v want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestReplayHTTP2StripsPseudosOriginForm(t *testing.T) {
	var (
		sawMethod, sawHost, sawProto, sawURI string
		leaked                               bool
	)
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMethod = r.Method
		sawHost = r.Host
		sawProto = r.Proto
		sawURI = r.RequestURI
		for name := range r.Header {
			if strings.HasPrefix(name, ":") {
				leaked = true
			}
		}
		if r.Header.Get(":method") != "" {
			leaked = true
		}
		_, _ = io.WriteString(w, "ok")
	}))
	px := startProxy(t, Options{})
	u := mustURL(t, originURL)
	f, err := px.Replay(context.Background(), &model.Flow{
		Method:   http.MethodGet,
		URL:      originURL + "/login",
		Host:     u.Host,
		Scheme:   "http",
		Protocol: model.FlowProtocolHTTP2,
		Request: model.HTTPMessage{
			Headers: []model.Header{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "http"},
				{Name: ":authority", Value: u.Host},
				{Name: ":path", Value: "/login"},
				{Name: "User-Agent", Value: "lab"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if leaked {
		t.Fatal("origin saw leading-colon header")
	}
	if sawMethod != http.MethodGet {
		t.Fatalf("method %q", sawMethod)
	}
	if sawHost != u.Host {
		t.Fatalf("host %q want %q (from :authority)", sawHost, u.Host)
	}
	if sawProto != "HTTP/1.1" {
		t.Fatalf("proto %q", sawProto)
	}
	if strings.HasPrefix(sawURI, "http") {
		t.Fatalf("not origin-form RequestURI %q", sawURI)
	}
	if f == nil || f.Status != 200 || f.Protocol != model.FlowProtocolHTTP11 {
		t.Fatalf("replay flow %+v", f)
	}
}

func TestReplayRequestStripsPseudos(t *testing.T) {
	stored := &model.Flow{
		Method:   http.MethodPost,
		URL:      "https://app.lab/login",
		Host:     "app.lab",
		Scheme:   "https",
		Protocol: model.FlowProtocolHTTP2,
		Request: model.HTTPMessage{
			Headers: []model.Header{
				{Name: ":method", Value: "POST"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "app.lab"},
				{Name: ":path", Value: "/login"},
				{Name: "Content-Type", Value: "text/plain"},
			},
			Body: []byte("x"),
		},
	}
	res := resolved{Selected: net.ParseIP("127.0.0.1"), Port: "443", Host: "app.lab"}
	req, err := replayRequest(context.Background(), stored, res, "app.lab", "443", "https")
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get(":method") != "" || req.Header.Get(":authority") != "" || req.Header.Get(":path") != "" {
		t.Fatalf("pseudos leaked: %v", req.Header)
	}
	if req.Host != "app.lab" {
		t.Fatalf("Host %q (want :authority)", req.Host)
	}
	if req.Method != http.MethodPost || req.URL.Path != "/login" {
		t.Fatalf("method=%s path=%s", req.Method, req.URL.Path)
	}
	if req.ProtoMajor == 2 {
		t.Fatalf("replay must be HTTP/1.1, proto %s", req.Proto)
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

func TestReplayHTTP2LiveOriginOnUsesH2(t *testing.T) {
	var sawProto string
	var leaked bool
	origin := startTLSOriginH2(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawProto = r.Proto
		for name := range r.Header {
			if strings.HasPrefix(name, ":") {
				leaked = true
			}
		}
		if r.URL.Path != "/login" {
			t.Errorf("path %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, "h2-replay")
	}))
	spec := loadSpec(t)
	spec.TLS.Upstream.InsecureSkipVerify = true
	spec.Protocols.HTTP2.Enabled = true
	spec.Protocols.HTTP2.Origin = true
	px := startProxy(t, Options{Spec: spec})
	u := mustURL(t, "https://"+origin+"/login")
	f, err := px.Replay(context.Background(), &model.Flow{
		Method:   http.MethodGet,
		URL:      "https://" + origin + "/login",
		Host:     u.Host,
		Scheme:   "https",
		Protocol: model.FlowProtocolHTTP2,
		Request: model.HTTPMessage{
			Headers: []model.Header{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: u.Host},
				{Name: ":path", Value: "/login"},
				{Name: "User-Agent", Value: "lab"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if leaked {
		t.Fatal("origin saw leading-colon header")
	}
	if sawProto != "HTTP/2.0" {
		t.Fatalf("live origin on must replay h2, proto %q", sawProto)
	}
	if f == nil || f.Status != 200 || f.Protocol != model.FlowProtocolHTTP2 || string(f.Response.Body) != "h2-replay" {
		t.Fatalf("replay flow %+v", f)
	}
}

func TestReplayHTTP2LiveOriginOffStaysH1(t *testing.T) {
	var sawProto string
	origin := startTLSOriginH2(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawProto = r.Proto
		_, _ = io.WriteString(w, "h1-replay")
	}))
	spec := loadSpec(t)
	spec.TLS.Upstream.InsecureSkipVerify = true
	spec.Protocols.HTTP2.Enabled = true
	px := startProxy(t, Options{Spec: spec})
	u := mustURL(t, "https://"+origin+"/login")
	f, err := px.Replay(context.Background(), &model.Flow{
		Method:   http.MethodGet,
		URL:      "https://" + origin + "/login",
		Host:     u.Host,
		Scheme:   "https",
		Protocol: model.FlowProtocolHTTP2,
		Request: model.HTTPMessage{
			Headers: []model.Header{
				{Name: ":method", Value: "GET"},
				{Name: ":path", Value: "/login"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sawProto != "HTTP/1.1" {
		t.Fatalf("live origin off must strip : and speak h1, proto %q", sawProto)
	}
	if f == nil || f.Status != 200 || f.Protocol != model.FlowProtocolHTTP11 || string(f.Response.Body) != "h1-replay" {
		t.Fatalf("replay flow %+v", f)
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

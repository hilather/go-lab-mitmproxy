package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/observability"
	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
)

func originIPPort(t *testing.T, addr string) (net.IP, int) {
	t.Helper()
	h, p := hostPort(t, addr)
	ip := net.ParseIP(h)
	if ip == nil {
		t.Fatalf("not an IP: %q", h)
	}
	return ip, p
}

func writeOrigHTTP(t *testing.T, addr, raw string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		_ = c.Close()
		t.Fatal(err)
	}
	return c
}

func readOrigHTTP(t *testing.T, c net.Conn) *http.Response {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestOrigDestMockedPOSTSucceeds(t *testing.T) {
	var got string
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "saved")
	}))
	ip, port := originIPPort(t, origin)
	px := startOrigDestProxy(t, ip, port, Options{})
	c := writeOrigHTTP(t, px.OrigDestAddr().String(),
		"POST /p HTTP/1.1\r\nHost: app.lab\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody")
	defer func() { _ = c.Close() }()
	resp := readOrigHTTP(t, c)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got != "body" {
		t.Fatalf("origin body %q", got)
	}
}

func TestOrigDestDirectConnectCloses(t *testing.T) {
	requireOrigDest(t)
	spec := loadSpec(t)
	spec.Listeners.OriginalDestination.Enabled = true
	spec.Listeners.OriginalDestination.Address = "127.0.0.1:0"
	rec := &recordingDial{}
	var px *Server
	px = startProxy(t, Options{
		Spec:        spec,
		DialContext: rec.wrap(nil),
		OriginalDst: func(net.Conn) (net.IP, int, error) {
			_, p, err := net.SplitHostPort(px.OrigDestAddr().String())
			if err != nil {
				return nil, 0, err
			}
			n, err := strconv.Atoi(p)
			if err != nil {
				return nil, 0, err
			}
			return net.ParseIP("127.0.0.1"), n, nil
		},
	})
	c := writeOrigHTTP(t, px.OrigDestAddr().String(), "GET / HTTP/1.1\r\nHost: app.lab\r\n\r\n")
	defer func() { _ = c.Close() }()
	buf := make([]byte, 32)
	n, err := c.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("direct-connect got %q", buf[:n])
	}
	if len(rec.Addrs()) != 0 {
		t.Fatalf("dialed %v", rec.Addrs())
	}
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("origdest") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("origdest") < 1 {
		t.Fatal("expected origdest reject")
	}
}

func TestOrigDestOriginFormOnProxyStill400(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	px := startOrigDestProxy(t, ip, 80, Options{})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "origin-form.txt"), nil)
}

func TestOrigDestH2CPrefaceCloses(t *testing.T) {
	origin, _ := startOrigin(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("origin must not be reached")
	}))
	ip, port := originIPPort(t, origin)
	px := startOrigDestProxy(t, ip, port, Options{})
	c := writeOrigHTTP(t, px.OrigDestAddr().String(), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	defer func() { _ = c.Close() }()
	buf := make([]byte, 32)
	n, err := c.Read(buf)
	if err == nil && n > 0 && strings.HasPrefix(string(buf[:n]), "HTTP/1.1 400") {
		t.Fatalf("preface became 400: %q", buf[:n])
	}
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("http2") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("http2") < 1 {
		t.Fatal("expected http2 reject")
	}
	if px.sessionCount() != 0 {
		t.Fatalf("h2c preface acquired a session: %d", px.sessionCount())
	}
}

func TestOrigDestWebSocketDisabledNoDial(t *testing.T) {
	var hits int
	origin, _ := startOrigin(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits++
		t.Error("origin must not be reached")
	}))
	ip, port := originIPPort(t, origin)
	rec := &recordingDial{}
	sink := NewNull()
	spec := loadSpec(t)
	spec.Protocols.WebSocket.Enabled = false
	px := startOrigDestProxy(t, ip, port, Options{
		Spec:        spec,
		Sink:        sink,
		DialContext: rec.wrap(nil),
	})
	c := writeOrigHTTP(t, px.OrigDestAddr().String(),
		"GET /ws HTTP/1.1\r\nHost: app.lab\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	defer func() { _ = c.Close() }()
	resp := readOrigHTTP(t, c)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if hits != 0 {
		t.Fatalf("origin hits=%d", hits)
	}
	if len(rec.Addrs()) != 0 {
		t.Fatalf("dialed %v", rec.Addrs())
	}
	if px.Metrics().Rejected("websocket") < 1 {
		t.Fatal("expected websocket reject")
	}
	found := false
	for _, f := range sink.Last() {
		if f.Protocol == model.FlowProtocolWebSocket && f.Error == "forbidden" && f.Status == http.StatusForbidden {
			found = true
		}
	}
	if !found {
		t.Fatalf("want websocket forbidden flow, got %+v", sink.Last())
	}
}

func TestOrigDestCONNECTStays400WhenConnectOff(t *testing.T) {
	rec := &recordingDial{}
	spec := loadSpec(t)
	spec.Protocols.Connect.Enabled = false
	px := startOrigDestProxy(t, net.ParseIP("127.0.0.1"), 443, Options{
		Spec:        spec,
		DialContext: rec.wrap(nil),
	})
	c := writeOrigHTTP(t, px.OrigDestAddr().String(),
		"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
	defer func() { _ = c.Close() }()
	resp := readOrigHTTP(t, c)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if px.Metrics().Rejected("connect") != 0 {
		t.Fatal("orig-dest CONNECT must not use protocols.connect")
	}
	if len(rec.Addrs()) != 0 {
		t.Fatalf("CONNECT dialed %v", rec.Addrs())
	}
}

func TestOrigDestHTTPNotSubjectToAbsoluteForm(t *testing.T) {
	var hits int
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = io.WriteString(w, "ok")
	}))
	ip, port := originIPPort(t, origin)
	spec := loadSpec(t)
	spec.Protocols.AbsoluteForm.Enabled = false
	px := startOrigDestProxy(t, ip, port, Options{Spec: spec})
	c := writeOrigHTTP(t, px.OrigDestAddr().String(),
		"GET /hello HTTP/1.1\r\nHost: app.lab\r\nConnection: close\r\n\r\n")
	defer func() { _ = c.Close() }()
	resp := readOrigHTTP(t, c)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if hits != 1 {
		t.Fatalf("hits=%d", hits)
	}
	if px.Metrics().Rejected("absolute_form") != 0 {
		t.Fatal("orig-dest HTTP must not use protocols.absoluteForm")
	}
}

func TestOrigDestTaggedCONNECTNoDial(t *testing.T) {
	rec := &recordingDial{}
	px := startOrigDestProxy(t, net.ParseIP("127.0.0.1"), 443, Options{
		DialContext: rec.wrap(nil),
	})
	c := writeOrigHTTP(t, px.OrigDestAddr().String(),
		"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
	defer func() { _ = c.Close() }()
	resp := readOrigHTTP(t, c)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(rec.Addrs()) != 0 {
		t.Fatalf("CONNECT dialed %v", rec.Addrs())
	}
}

func TestOrigDestAbsoluteFormIMDSDoesNotDialIMDS(t *testing.T) {
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	ip, port := originIPPort(t, origin)
	rec := &recordingDial{}
	px := startOrigDestProxy(t, ip, port, Options{
		DialContext: rec.wrap(func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}),
	})
	c := writeOrigHTTP(t, px.OrigDestAddr().String(),
		"GET http://169.254.169.254/ HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: close\r\n\r\n")
	defer func() { _ = c.Close() }()
	resp := readOrigHTTP(t, c)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	want := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	for _, a := range rec.Addrs() {
		if strings.Contains(a, "169.254.169.254") {
			t.Fatalf("dialed IMDS %v", rec.Addrs())
		}
	}
	if len(rec.Addrs()) == 0 || rec.Addrs()[0] != want {
		t.Fatalf("dialed %v want %s", rec.Addrs(), want)
	}
}

func TestOrigDestHTTPGetOneGateSession(t *testing.T) {
	held := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(held) })
		<-release
		_, _ = io.WriteString(w, "ok")
	}))
	ip, port := originIPPort(t, origin)
	spec := loadSpec(t)
	spec.Proxy.Admission.MaxSessions = 1
	spec.Proxy.Admission.MaxSessionsPerIP = 1
	px := startOrigDestProxy(t, ip, port, Options{Spec: spec})

	c1 := writeOrigHTTP(t, px.OrigDestAddr().String(),
		"GET /one HTTP/1.1\r\nHost: app.lab\r\nConnection: close\r\n\r\n")
	defer func() { _ = c1.Close() }()
	select {
	case <-held:
	case <-time.After(2 * time.Second):
		t.Fatal("origin was not reached")
	}
	if px.sessionCount() != 1 {
		t.Fatalf("sessions=%d want 1", px.sessionCount())
	}

	c2 := writeOrigHTTP(t, px.OrigDestAddr().String(),
		"GET /two HTTP/1.1\r\nHost: app.lab\r\nConnection: close\r\n\r\n")
	defer func() { _ = c2.Close() }()
	resp2 := readOrigHTTP(t, c2)
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("admission status %d", resp2.StatusCode)
	}
	if px.sessionCount() != 1 {
		t.Fatalf("admission leaked a slot: sessions=%d", px.sessionCount())
	}

	close(release)
	resp1 := readOrigHTTP(t, c1)
	defer func() { _ = resp1.Body.Close() }()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first GET status %d", resp1.StatusCode)
	}
	deadline := time.Now().Add(2 * time.Second)
	for px.sessionCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.sessionCount() != 0 {
		t.Fatalf("sessions=%d after release", px.sessionCount())
	}

	c3 := writeOrigHTTP(t, px.OrigDestAddr().String(),
		"GET /three HTTP/1.1\r\nHost: app.lab\r\nConnection: close\r\n\r\n")
	defer func() { _ = c3.Close() }()
	resp3 := readOrigHTTP(t, c3)
	defer func() { _ = resp3.Body.Close() }()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("slot not reusable: status %d", resp3.StatusCode)
	}
}

func TestOrigDestRecoverFailClosesNoDial(t *testing.T) {
	requireOrigDest(t)
	spec := loadSpec(t)
	spec.Listeners.OriginalDestination.Enabled = true
	spec.Listeners.OriginalDestination.Address = "127.0.0.1:0"
	rec := &recordingDial{}
	px := startProxy(t, Options{
		Spec:        spec,
		DialContext: rec.wrap(nil),
		OriginalDst: func(net.Conn) (net.IP, int, error) {
			return nil, 0, errors.New("no dest")
		},
	})
	c := writeOrigHTTP(t, px.OrigDestAddr().String(), "GET / HTTP/1.1\r\nHost: app.lab\r\n\r\n")
	defer func() { _ = c.Close() }()
	buf := make([]byte, 8)
	_, _ = c.Read(buf)
	if len(rec.Addrs()) != 0 {
		t.Fatalf("dialed %v", rec.Addrs())
	}
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("origdest") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("origdest") < 1 {
		t.Fatal("expected origdest reject")
	}
}

func TestOrigDestDestIMDSDeniedNoDial(t *testing.T) {
	rec := &recordingDial{}
	px := startOrigDestProxy(t, net.ParseIP("169.254.169.254"), 80, Options{
		DialContext: rec.wrap(nil),
	})
	c := writeOrigHTTP(t, px.OrigDestAddr().String(), "GET / HTTP/1.1\r\nHost: metadata\r\n\r\n")
	defer func() { _ = c.Close() }()
	buf := make([]byte, 8)
	_, _ = c.Read(buf)
	if len(rec.Addrs()) != 0 {
		t.Fatalf("dialed %v", rec.Addrs())
	}
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("target_denied") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("target_denied") < 1 {
		t.Fatal("expected target_denied")
	}
}

func TestOrigDestSOCKSCloses(t *testing.T) {
	px := startOrigDestProxy(t, net.ParseIP("127.0.0.1"), 80, Options{})
	c, err := net.DialTimeout("tcp", px.OrigDestAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if n != 0 && err == nil {
		t.Fatalf("SOCKS got %q", buf[:n])
	}
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("socks") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("socks") < 1 {
		t.Fatal("expected socks reject on orig-dest")
	}
}

func TestOrigDestEmptySNINonEmptyHostsNoDial(t *testing.T) {
	rec := &recordingDial{}
	spec := loadSpec(t)
	spec.TLS.Intercept = true
	spec.TLS.Ports = []int{443}
	spec.TLS.Hosts = []string{"app.lab"}
	px := startOrigDestProxy(t, net.ParseIP("127.0.0.1"), 443, Options{
		Spec:        spec,
		DialContext: rec.wrap(nil),
	})
	hello := minimalClientHello("")
	c, err := net.DialTimeout("tcp", px.OrigDestAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(hello); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_, _ = c.Read(buf)
	deadline := time.Now().Add(2 * time.Second)
	for len(rec.Addrs()) == 0 && time.Now().Before(deadline) {
		if px.Metrics().TLSIntercepts("tls_handshake") >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(rec.Addrs()) != 0 {
		t.Fatalf("empty SNI dialed %v", rec.Addrs())
	}
}

func TestOrigDestDisabledDoesNotBind(t *testing.T) {
	px := startProxy(t, Options{})
	if px.OrigDestAddr() != nil || px.OrigDestAccepting() {
		t.Fatal("orig-dest bound while disabled")
	}
}

func TestReplayHairpinOrigDest(t *testing.T) {
	origin, _ := startOrigin(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	ip, port := originIPPort(t, origin)
	px := startOrigDestProxy(t, ip, port, Options{})
	od := px.OrigDestAddr().String()
	_, err := px.Replay(context.Background(), &model.Flow{
		Method:   http.MethodGet,
		URL:      "http://" + od + "/",
		Host:     od,
		Scheme:   "http",
		Protocol: model.FlowProtocolHTTP11,
	})
	if err == nil {
		t.Fatal("orig-dest bind must hairpin")
	}
}

func TestOrigDestOffEvaluate(t *testing.T) {
	p := observability.Evaluate(observability.Facts{
		ProxyBound: true, StoreUp: true, MgmtOff: true, CAReady: true, OrigDestOff: true,
	})
	if !p.Ready {
		t.Fatalf("OrigDestOff: %+v", p)
	}
}

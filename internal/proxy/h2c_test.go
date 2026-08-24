package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
	"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm"
	"github.com/hilather/go-lab-mitmproxy/internal/wsx"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestH2CPRICloseBeforeAcquire(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
		_, _ = io.WriteString(w, "ok")
	}))
	spec := loadSpec(t)
	spec.Proxy.Admission.MaxSessions = 1
	px := startProxy(t, Options{Spec: spec})

	held := make(chan struct{})
	go func() {
		tr := &http.Transport{
			Proxy:             http.ProxyURL(mustURL(t, "http://"+px.Addr().String())),
			ForceAttemptHTTP2: false,
		}
		defer tr.CloseIdleConnections()
		close(held)
		req := mustRequest(t, http.MethodGet, originURL+"/hold")
		_, _ = tr.RoundTrip(req)
	}()
	<-held
	deadline := time.Now().Add(2 * time.Second)
	for px.sessionCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.sessionCount() < 1 {
		t.Fatal("hold GET did not acquire")
	}

	raw, err := os.ReadFile(testdataProxy(t, "pri-close.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("PRI * HTTP/2.0")) {
		t.Fatal("pri-close transcript missing preface")
	}

	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteRaw([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := c.Conn.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("flag-off PRI got response %q", buf[:n])
	}
	deadline = time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("http2") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("http2") < 1 {
		t.Fatal("expected reject reason=http2")
	}
	if px.Metrics().Rejected("admission") != 0 {
		t.Fatalf("PRI acquired: admission=%d", px.Metrics().Rejected("admission"))
	}
}

func TestH2CPRILeftover(t *testing.T) {
	raw, err := os.ReadFile(testdataProxy(t, "h2c-pri-leftover.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("PRI * HTTP/2.0")) || !bytes.Contains(raw, []byte("SM")) {
		t.Fatal("h2c-pri-leftover transcript missing leftover contract")
	}

	var sawURI string
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawURI = r.URL.RequestURI()
		_, _ = io.WriteString(w, "ok")
	}))
	spec := loadSpec(t)
	spec.Protocols.HTTP2.ClientCleartext = true
	px := startProxy(t, Options{Spec: spec})

	cc := dialH2C(t, px.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := mustRequest(t, http.MethodGet, originURL+"/hello")
	req = req.WithContext(ctx)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("leftover h2c GET: %v (ServeConn must not re-read the 24-byte preface from the raw conn)", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if sawURI != "/hello" {
		t.Fatalf("origin URI %q", sawURI)
	}
}

func TestH2CRegularGET(t *testing.T) {
	var sawHost, sawURI, sawMethod string
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHost = r.Host
		sawURI = r.URL.RequestURI()
		sawMethod = r.Method
		if strings.HasPrefix(r.RequestURI, "http://") {
			t.Errorf("origin saw absolute-form %q", r.RequestURI)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	spec := loadSpec(t)
	spec.Protocols.HTTP2.ClientCleartext = true
	px := startProxy(t, Options{Spec: spec})
	cc := dialH2C(t, px.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := mustRequest(t, http.MethodGet, originURL+"/hello")
	req = req.WithContext(ctx)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	u := mustURL(t, originURL)
	if sawHost != u.Host || sawURI != "/hello" || sawMethod != http.MethodGet {
		t.Fatalf("origin host=%q uri=%q method=%q", sawHost, sawURI, sawMethod)
	}
}

func TestH2CExpectStripped(t *testing.T) {
	var got, expect string
	_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expect = r.Header.Get("Expect")
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		_, _ = io.WriteString(w, "ok")
	}))
	spec := loadSpec(t)
	spec.Protocols.HTTP2.ClientCleartext = true
	px := startProxy(t, Options{Spec: spec})
	host := mustURL(t, originURL).Host
	fr, c := h2cRawClient(t, px.Addr().String())
	defer func() { _ = c.Close() }()
	writeH2CHeaders(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodPost},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: host},
		{Name: ":path", Value: "/e"},
		{Name: "expect", Value: "100-continue"},
		{Name: "content-type", Value: "text/plain"},
	}, false)
	if err := fr.WriteData(1, true, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	st := readH2CStatus(t, fr, 1)
	if st != http.StatusOK {
		t.Fatalf("status %d (Expect must be stripped, not 500 hijack)", st)
	}
	if expect != "" {
		t.Fatalf("origin saw Expect=%q", expect)
	}
	if got != "ping" {
		t.Fatalf("origin body %q", got)
	}
}

func TestH2CSchemeHTTPS400(t *testing.T) {
	spec := loadSpec(t)
	spec.Protocols.HTTP2.ClientCleartext = true
	px := startProxy(t, Options{Spec: spec})
	cc := dialH2C(t, px.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), string(domainerr.CodeValidationFailed)) {
		t.Fatalf("body %q", body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("absolute_https") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("absolute_https") < 1 {
		t.Fatal("expected reject reason=absolute_https")
	}
}

func TestH2CConnectRawTunnel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 16)
		n, _ := c.Read(buf)
		got <- append([]byte(nil), buf[:n]...)
		_, _ = c.Write([]byte("pong"))
	}()

	spec := loadSpec(t)
	spec.Protocols.HTTP2.ClientCleartext = true
	px := startProxy(t, Options{Spec: spec})
	fr, c := h2cRawClient(t, px.Addr().String())
	defer func() { _ = c.Close() }()
	writeH2CHeaders(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":authority", Value: ln.Addr().String()},
	}, false)
	st := readH2CStatus(t, fr, 1)
	if st != http.StatusOK {
		t.Fatalf("status %d want 200 (no HTTP/1.1 200)", st)
	}
	if err := fr.WriteData(1, false, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-got:
		if string(b) != "ping" {
			t.Fatalf("origin %q (want raw splice, not HTTP)", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("origin did not see spliced DATA")
	}
	if string(readH2CData(t, fr, 1)) != "pong" {
		t.Fatal("want origin DATA pong")
	}
}

func TestH2CConnectRawIdleTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	originDone := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		c, err := ln.Accept()
		if err != nil {
			originDone <- 0
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 8)
		_, _ = c.Read(buf)
		originDone <- time.Since(start)
	}()

	spec := loadSpec(t)
	spec.Protocols.HTTP2.ClientCleartext = true
	spec.Proxy.Admission.IdleTimeout = 200 * time.Millisecond
	spec.Proxy.Admission.SessionTimeout = 5 * time.Second
	px := startProxy(t, Options{Spec: spec})
	fr, c := h2cRawClient(t, px.Addr().String())
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	writeH2CHeaders(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":authority", Value: ln.Addr().String()},
	}, false)
	st := readH2CStatus(t, fr, 1)
	if st != http.StatusOK {
		t.Fatalf("status %d want 200", st)
	}
	select {
	case d := <-originDone:
		if d == 0 {
			t.Fatal("origin accept failed")
		}
		if d > time.Second {
			t.Fatalf("origin FD lived %s (idleTimeout=200ms)", d)
		}
	case <-time.After(time.Second):
		t.Fatal("origin FD outlived idleTimeout")
	}
	start := time.Now()
	deadline := start.Add(time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		if rst, ok := f.(*http2.RSTStreamFrame); ok && rst.StreamID == 1 {
			return
		}
		if df, ok := f.(*http2.DataFrame); ok && df.StreamID == 1 && df.StreamEnded() {
			return
		}
	}
	t.Fatal("idleTimeout did not RST or DATA END_STREAM")
}

func TestH2CConnectIntercept(t *testing.T) {
	var sawURI string
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawURI = r.URL.RequestURI()
		_, _ = io.WriteString(w, "ok")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	spec.Protocols.HTTP2.ClientCleartext = true
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	fr, c := h2cRawClient(t, px.Addr().String())
	defer func() { _ = c.Close() }()
	authority := net.JoinHostPort("app.lab", strconv.Itoa(port))
	writeH2CHeaders(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":authority", Value: authority},
	}, false)
	st := readH2CStatus(t, fr, 1)
	if st != http.StatusOK {
		t.Fatalf("status %d want 200", st)
	}
	tun := &h2cTunnelConn{fr: fr, c: c, id: 1}
	tlsConn := tls.Client(tun, &tls.Config{
		ServerName: "app.lab",
		RootCAs:    px.Authority().CertPool(),
		NextProtos: []string{tlsmitm.ALPN},
		MinVersion: tls.VersionTLS12,
	})
	defer func() { _ = tlsConn.Close() }()
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(tlsConn, "GET /hello HTTP/1.1\r\nHost: app.lab\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if sawURI != "/hello" {
		t.Fatalf("origin URI %q", sawURI)
	}
	deadline := time.Now().Add(2 * time.Second)
	var intercepted bool
	for time.Now().Before(deadline) {
		for _, f := range sink.Last() {
			if f.Intercepted && f.URL != "" && strings.Contains(f.URL, "/hello") {
				intercepted = true
			}
		}
		if intercepted {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !intercepted {
		t.Fatalf("want intercepted inner GET, got %+v", sink.Last())
	}
}

func TestH2CConnectHandshakeFailNoDATATunnel(t *testing.T) {
	var hits atomic.Int32
	got := make(chan []byte, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		got <- append([]byte(nil), buf[:n]...)
		hits.Add(1)
	}()
	_, port := hostPort(t, ln.Addr().String())
	sink := NewNull()
	spec := loadSpec(t)
	spec.Protocols.HTTP2.ClientCleartext = true
	spec.TLS.Intercept = true
	spec.TLS.Ports = []int{port}
	px := startProxy(t, Options{Spec: spec, Sink: sink})
	fr, c := h2cRawClient(t, px.Addr().String())
	defer func() { _ = c.Close() }()
	writeH2CHeaders(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":authority", Value: ln.Addr().String()},
	}, false)
	st := readH2CStatus(t, fr, 1)
	if st != http.StatusOK {
		t.Fatalf("status %d want 200 then handshake", st)
	}
	if err := fr.WriteData(1, false, []byte("GET /secret HTTP/1.1\r\nHost: "+ln.Addr().String()+"\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	sawRST := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			break
		}
		switch hf := f.(type) {
		case *http2.RSTStreamFrame:
			if hf.StreamID == 1 {
				sawRST = true
				deadline = time.Time{}
			}
		case *http2.DataFrame:
			if hf.StreamID == 1 && hf.StreamEnded() {
				deadline = time.Time{}
			}
			if hf.StreamID == 1 && strings.Contains(string(hf.Data()), "/secret") {
				t.Fatalf("DATA tunnel of plaintext GET %q", hf.Data())
			}
		}
	}

	var sawHandshake bool
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range sink.Last() {
			if f.Error == tlsmitm.ResultTLSHandshake {
				sawHandshake = true
			}
		}
		if sawHandshake {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sawHandshake {
		t.Fatalf("want Error=tls_handshake, got %+v rst=%v", sink.Last(), sawRST)
	}
	select {
	case b := <-got:
		if strings.Contains(string(b), "/secret") || strings.HasPrefix(string(b), "GET ") {
			t.Fatalf("blind-tunneled client bytes %q", b)
		}
	case <-time.After(500 * time.Millisecond):
	}
	if px.Metrics().TLSIntercepts(tlsmitm.ResultTLSHandshake) < 1 {
		t.Fatal("missing tls_handshake metric")
	}
	if !sawRST {
		t.Fatal("handshake fail must RST_STREAM, not DATA-tunnel")
	}
}

func TestH2CConnectMissingPort400(t *testing.T) {
	spec := loadSpec(t)
	spec.Protocols.HTTP2.ClientCleartext = true
	px := startProxy(t, Options{Spec: spec})
	fr, c := h2cRawClient(t, px.Addr().String())
	defer func() { _ = c.Close() }()
	writeH2CHeaders(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":authority", Value: "app.lab"},
	}, true)
	st := readH2CStatus(t, fr, 1)
	if st != http.StatusBadRequest {
		t.Fatalf("status %d want 400", st)
	}
}

func TestH2CConnectProtocolRSTFlagOff(t *testing.T) {
	spec := loadSpec(t)
	spec.Protocols.HTTP2.ClientCleartext = true
	px := startProxy(t, Options{Spec: spec})
	fr, c := h2cRawClient(t, px.Addr().String())
	defer func() { _ = c.Close() }()
	writeH2CHeaders(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":protocol", Value: "websocket"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "app.lab"},
		{Name: ":path", Value: "/ws"},
	}, false)
	expectH2CRST(t, fr, 1, http2.ErrCodeProtocol)
	if px.Metrics().Rejected("http2") < 1 {
		t.Fatal("expected reject reason=http2")
	}
}

func TestH2CConnectWebSocketExtendedConnect(t *testing.T) {
	origin := echoWSOrigin(t)
	spec := loadSpec(t)
	spec.Protocols.HTTP2.ClientCleartext = true
	spec.Protocols.HTTP2.ExtendedConnect = true
	px := startProxy(t, Options{Spec: spec})
	fr, c := h2cRawClient(t, px.Addr().String())
	defer func() { _ = c.Close() }()
	writeH2CHeaders(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":protocol", Value: "websocket"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: origin},
		{Name: ":path", Value: "/ws"},
		{Name: "sec-websocket-version", Value: "13"},
	}, false)
	st := readH2CStatus(t, fr, 1)
	if st != http.StatusOK {
		t.Fatalf("status %d want 200", st)
	}
	var payload bytes.Buffer
	if err := wsx.WriteFrame(&payload, wsx.Frame{
		Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("h2cws"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteData(1, false, payload.Bytes()); err != nil {
		t.Fatal(err)
	}
	echo := readH2CWebSocketFrame(t, fr, 1)
	if echo.Opcode != wsx.OpcodeText || string(echo.Payload) != "h2cws" {
		t.Fatalf("echo %+v", echo)
	}
}

func TestH2COrigDestTaggedCONNECT400(t *testing.T) {
	requireOrigDest(t)
	rec := &recordingDial{}
	spec := loadSpec(t)
	spec.Protocols.HTTP2.ClientCleartext = true
	px := startOrigDestProxy(t, net.ParseIP("127.0.0.1"), 443, Options{
		DialContext: rec.wrap(nil),
		Spec:        spec,
	})
	fr, c := h2cRawClient(t, px.OrigDestAddr().String())
	defer func() { _ = c.Close() }()
	writeH2CHeaders(t, fr, 1, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":authority", Value: "127.0.0.1:443"},
	}, true)
	st := readH2CStatus(t, fr, 1)
	if st != http.StatusBadRequest {
		t.Fatalf("status %d want 400", st)
	}
	if len(rec.Addrs()) != 0 {
		t.Fatalf("CONNECT dialed %v", rec.Addrs())
	}
}

func TestH2COrigDestRegularDialsDestIP(t *testing.T) {
	requireOrigDest(t)
	var sawURI string
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawURI = r.URL.RequestURI()
		_, _ = io.WriteString(w, "ok")
	}))
	ip, port := originIPPort(t, origin)
	rec := &recordingDial{}
	spec := loadSpec(t)
	spec.Protocols.HTTP2.ClientCleartext = true
	px := startOrigDestProxy(t, ip, port, Options{
		Spec: spec,
		DialContext: rec.wrap(func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}),
	})
	cc := dialH2C(t, px.OrigDestAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://169.254.169.254/hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if sawURI != "/hello" {
		t.Fatalf("origin URI %q", sawURI)
	}
	want := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	found := false
	for _, a := range rec.Addrs() {
		if a == want {
			found = true
		}
		if strings.HasPrefix(a, "169.254.169.254") {
			t.Fatalf("dialed IMDS %v", rec.Addrs())
		}
	}
	if !found {
		t.Fatalf("dialed %v want dest %s", rec.Addrs(), want)
	}
}

func dialH2C(t *testing.T, addr string) *http2.ClientConn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(c)
	if err != nil {
		t.Fatalf("h2c preface/SETTINGS: %v (leftover SM must be read from bufrw, not a 24-byte ReadFull on the raw conn)", err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func h2cRawClient(t *testing.T, addr string) (*http2.Framer, net.Conn) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(http2.ClientPreface)); err != nil {
		_ = c.Close()
		t.Fatal(err)
	}
	fr := http2.NewFramer(c, bufio.NewReader(c))
	if err := fr.WriteSettings(); err != nil {
		_ = c.Close()
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			_ = c.Close()
			t.Fatalf("settings: %v", err)
		}
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			if err := fr.WriteSettingsAck(); err != nil {
				_ = c.Close()
				t.Fatal(err)
			}
			return fr, c
		}
	}
	_ = c.Close()
	t.Fatal("no server SETTINGS")
	return fr, c
}

func writeH2CHeaders(t *testing.T, fr *http2.Framer, id uint32, fields []hpack.HeaderField, endStream bool) {
	t.Helper()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, hf := range fields {
		if err := enc.WriteField(hf); err != nil {
			t.Fatal(err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      id,
		BlockFragment: buf.Bytes(),
		EndHeaders:    true,
		EndStream:     endStream,
	}); err != nil {
		t.Fatal(err)
	}
}

func readH2CStatus(t *testing.T, fr *http2.Framer, id uint32) int {
	t.Helper()
	dec := hpack.NewDecoder(4096, nil)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch hf := f.(type) {
		case *http2.RSTStreamFrame:
			if hf.StreamID == id {
				t.Fatalf("RST %v", hf.ErrCode)
			}
		case *http2.HeadersFrame:
			if hf.StreamID != id {
				continue
			}
			headers, err := dec.DecodeFull(hf.HeaderBlockFragment())
			if err != nil {
				t.Fatal(err)
			}
			for _, h := range headers {
				if h.Name == ":status" {
					var n int
					for _, c := range h.Value {
						n = n*10 + int(c-'0')
					}
					return n
				}
			}
		}
	}
	t.Fatal("no response HEADERS")
	return 0
}

func readH2CData(t *testing.T, fr *http2.Framer, id uint32) []byte {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch hf := f.(type) {
		case *http2.RSTStreamFrame:
			if hf.StreamID == id {
				t.Fatalf("RST %v", hf.ErrCode)
			}
		case *http2.DataFrame:
			if hf.StreamID == id {
				return append([]byte(nil), hf.Data()...)
			}
		}
	}
	t.Fatal("no DATA")
	return nil
}

func expectH2CRST(t *testing.T, fr *http2.Framer, id uint32, code http2.ErrCode) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		rst, ok := f.(*http2.RSTStreamFrame)
		if !ok || rst.StreamID != id {
			continue
		}
		if rst.ErrCode != code {
			t.Fatalf("RST %v want %v", rst.ErrCode, code)
		}
		return
	}
	t.Fatal("no RST_STREAM")
}

func readH2CWebSocketFrame(t *testing.T, fr *http2.Framer, id uint32) wsx.Frame {
	t.Helper()
	var buf bytes.Buffer
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		df, ok := f.(*http2.DataFrame)
		if !ok || df.StreamID != id {
			continue
		}
		buf.Write(df.Data())
		frame, werr := wsx.ReadFrame(&buf, 0)
		if werr == nil {
			return frame
		}
	}
	t.Fatal("no websocket frame")
	return wsx.Frame{}
}

// h2cTunnelConn is one CONNECT stream as a net.Conn (DATA in/out).
type h2cTunnelConn struct {
	fr *http2.Framer
	c  net.Conn
	id uint32
	r  bytes.Buffer
}

func (t *h2cTunnelConn) Read(p []byte) (int, error) {
	if t.r.Len() > 0 {
		return t.r.Read(p)
	}
	for {
		f, err := t.fr.ReadFrame()
		if err != nil {
			return 0, err
		}
		switch hf := f.(type) {
		case *http2.DataFrame:
			if hf.StreamID != t.id {
				continue
			}
			if n := len(hf.Data()); n > 0 {
				_ = t.fr.WriteWindowUpdate(t.id, uint32(n))
				_ = t.fr.WriteWindowUpdate(0, uint32(n))
				t.r.Write(hf.Data())
			}
			if hf.StreamEnded() && t.r.Len() == 0 {
				return 0, io.EOF
			}
			if t.r.Len() > 0 {
				return t.r.Read(p)
			}
		case *http2.RSTStreamFrame:
			if hf.StreamID == t.id {
				return 0, io.EOF
			}
		case *http2.GoAwayFrame:
			return 0, io.EOF
		case *http2.PingFrame:
			if !hf.IsAck() {
				_ = t.fr.WritePing(true, hf.Data)
			}
		}
	}
}

func (t *h2cTunnelConn) Write(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		chunk := p[n:]
		if len(chunk) > 16384 {
			chunk = chunk[:16384]
		}
		if err := t.fr.WriteData(t.id, false, chunk); err != nil {
			return n, err
		}
		n += len(chunk)
	}
	return n, nil
}

func (t *h2cTunnelConn) Close() error {
	_ = t.fr.WriteData(t.id, true, nil)
	return t.c.Close()
}

func (t *h2cTunnelConn) LocalAddr() net.Addr                { return t.c.LocalAddr() }
func (t *h2cTunnelConn) RemoteAddr() net.Addr               { return t.c.RemoteAddr() }
func (t *h2cTunnelConn) SetDeadline(tm time.Time) error     { return t.c.SetDeadline(tm) }
func (t *h2cTunnelConn) SetReadDeadline(tm time.Time) error { return t.c.SetReadDeadline(tm) }
func (t *h2cTunnelConn) SetWriteDeadline(tm time.Time) error {
	return t.c.SetWriteDeadline(tm)
}

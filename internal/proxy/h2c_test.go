package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
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

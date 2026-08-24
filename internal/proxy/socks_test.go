package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/compiler"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/observability"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
	"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm"
)

func socks5Spec(t *testing.T) model.Spec {
	t.Helper()
	spec := loadSpec(t)
	spec.Listeners.Proxy.AcceptSOCKS5 = true
	return spec
}

func socks4Spec(t *testing.T) model.Spec {
	t.Helper()
	spec := loadSpec(t)
	spec.Listeners.Proxy.AcceptSOCKS4 = true
	return spec
}

func socks5BindSpec(t *testing.T) model.Spec {
	t.Helper()
	spec := socks5Spec(t)
	spec.Listeners.Proxy.AcceptBind = true
	return spec
}

func socks4BindSpec(t *testing.T) model.Spec {
	t.Helper()
	spec := socks4Spec(t)
	spec.Listeners.Proxy.AcceptBind = true
	return spec
}

func socks5UDPSpec(t *testing.T) model.Spec {
	t.Helper()
	spec := socks5Spec(t)
	spec.Listeners.Proxy.AcceptUDPAssociate = true
	return spec
}

func bePort(p int) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(p))
	return b[:]
}

func ipv4Port(t *testing.T, addr string) (ip []byte, port int, host string) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	parsed := net.ParseIP(h).To4()
	if parsed == nil {
		t.Fatalf("not ipv4 %q", h)
	}
	return parsed, n, addr
}

func socksDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func writeAll(t *testing.T, c net.Conn, p []byte) {
	t.Helper()
	if _, err := c.Write(p); err != nil {
		t.Fatal(err)
	}
}

func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	p := make([]byte, n)
	if _, err := io.ReadFull(c, p); err != nil {
		t.Fatal(err)
	}
	return p
}

func socks5GreetingOK(t *testing.T, c net.Conn) {
	t.Helper()
	writeAll(t, c, []byte{0x05, 0x01, 0x00})
	got := readN(t, c, 2)
	if got[0] != 0x05 || got[1] != 0x00 {
		t.Fatalf("greeting reply %x want 05 00", got)
	}
}

func TestSOCKS5ConnectHTTPOrigin(t *testing.T) {
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hello" {
			t.Errorf("path %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, "socks-ok")
	}))
	sink := NewNull()
	px := startProxy(t, Options{Spec: socks5Spec(t), Sink: sink})
	ip, port, host := ipv4Port(t, origin)
	playSOCKSTranscript(t, px.Addr().String(), testdataProxy(t, "socks5-connect.txt"), map[string]string{
		"IPV4": hex.EncodeToString(ip),
		"PORT": hex.EncodeToString(bePort(port)),
		"HOST": host,
	})
	found := false
	for _, f := range sink.Last() {
		if f.Protocol == model.FlowProtocolSOCKS5 && f.Via == "socks5" && f.Method == http.MethodConnect && f.SOCKS != nil {
			found = true
			if f.SOCKS.Command != "connect" || f.SOCKS.Version != 5 {
				t.Fatalf("SOCKS %+v", f.SOCKS)
			}
		}
	}
	if !found {
		t.Fatalf("missing socks5 flow: %+v", sink.Last())
	}
	if px.Metrics().Socks("ok") < 1 {
		t.Fatal("expected socks ok")
	}
}

func TestSOCKS5IMDSDoesNotDial(t *testing.T) {
	rec := &recordingDial{}
	px := startProxy(t, Options{
		Spec:        socks5Spec(t),
		DialContext: rec.wrap(nil),
	})
	playSOCKSTranscript(t, px.Addr().String(), testdataProxy(t, "socks5-imds.txt"), nil)
	if got := rec.Addrs(); len(got) != 0 {
		t.Fatalf("dialed %v", got)
	}
	if px.Metrics().Rejected("target_denied") < 1 {
		t.Fatal("expected target_denied")
	}
	if px.Metrics().Socks("denied") < 1 {
		t.Fatal("expected socks denied")
	}
}

func TestSOCKS4OffTranscript(t *testing.T) {
	px := startProxy(t, Options{})
	playSOCKSTranscript(t, px.Addr().String(), testdataProxy(t, "socks4-off.txt"), nil)
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("socks") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("socks") < 1 {
		t.Fatal("expected socks reject")
	}
}

func TestSOCKS5OffStillCloses(t *testing.T) {
	spec := loadSpec(t)
	spec.Listeners.Proxy.AcceptSOCKS5 = false
	spec.Listeners.Proxy.AcceptSOCKS4 = true
	px := startProxy(t, Options{Spec: spec})
	c := socksDial(t, px.Addr().String())
	writeAll(t, c, []byte{0x05, 0x01, 0x00})
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if n != 0 && err == nil {
		t.Fatalf("got %q; want close", buf[:n])
	}
	if err == nil {
		t.Fatal("expected close")
	}
}

func TestSOCKS5NoAuthRequired(t *testing.T) {
	px := startProxy(t, Options{Spec: socks5Spec(t)})
	c := socksDial(t, px.Addr().String())
	writeAll(t, c, []byte{0x05, 0x01, 0x02})
	got := readN(t, c, 2)
	if got[0] != 0x05 || got[1] != 0xff {
		t.Fatalf("got %x want 05 ff", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("socks_auth") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("socks_auth") < 1 || px.Metrics().Socks("auth") < 1 {
		t.Fatal("expected socks_auth")
	}
}

func TestSOCKS5PrefersNoAuth(t *testing.T) {
	px := startProxy(t, Options{Spec: socks5Spec(t)})
	c := socksDial(t, px.Addr().String())
	writeAll(t, c, []byte{0x05, 0x02, 0x02, 0x00})
	got := readN(t, c, 2)
	if got[0] != 0x05 || got[1] != 0x00 {
		t.Fatalf("got %x want 05 00", got)
	}
}

func TestSOCKS5BindCommand(t *testing.T) {
	// acceptSOCKS5 on, acceptBind off (D58): BIND stays 05 07.
	px := startProxy(t, Options{Spec: socks5Spec(t)})
	c := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c)
	writeAll(t, c, []byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80})
	got := readN(t, c, 10)
	if got[0] != 0x05 || got[1] != 0x07 {
		t.Fatalf("got %x want 05 07", got)
	}
	if px.Metrics().Rejected("socks_command") < 1 || px.Metrics().Socks("command") < 1 {
		t.Fatal("expected socks_command")
	}
}

func TestSOCKS5UDPCommand(t *testing.T) {
	// acceptSOCKS5 on, acceptUDPAssociate off (D59): UDP stays 05 07.
	px := startProxy(t, Options{Spec: socks5Spec(t)})
	c := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c)
	writeAll(t, c, []byte{0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 80})
	got := readN(t, c, 10)
	if got[0] != 0x05 || got[1] != 0x07 {
		t.Fatalf("udp rep %x want 05 07", got)
	}
	if px.Metrics().Rejected("socks_command") < 1 || px.Metrics().Socks("command") < 1 {
		t.Fatal("expected socks_command")
	}
}

func TestSOCKS5HairpinDenied(t *testing.T) {
	rec := &recordingDial{}
	px := startProxy(t, Options{
		Spec:        socks5Spec(t),
		DialContext: rec.wrap(nil),
	})
	ip, port, _ := ipv4Port(t, px.Addr().String())
	c := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c)
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, ip...)
	req = append(req, bePort(port)...)
	writeAll(t, c, req)
	got := readN(t, c, 10)
	if got[1] != 0x02 {
		t.Fatalf("hairpin rep %x want 05 02", got)
	}
	if len(rec.Addrs()) != 0 {
		t.Fatalf("hairpin dialed %v", rec.Addrs())
	}
}

func TestSOCKS5IPv6SuccessUnspecified(t *testing.T) {
	_, originURL := startOriginOn(t, "tcp", "[::1]:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "v6")
	}))
	host, pstr, err := net.SplitHostPort(mustHost(t, originURL))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(pstr)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil {
		t.Fatalf("want ipv6 origin got %q", host)
	}
	px := startProxy(t, Options{Spec: socks5Spec(t)})
	c := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c)
	req := []byte{0x05, 0x01, 0x00, 0x04}
	req = append(req, ip.To16()...)
	req = append(req, bePort(port)...)
	writeAll(t, c, req)
	got := readN(t, c, 22)
	if got[0] != 0x05 || got[1] != 0x00 || got[3] != 0x04 {
		t.Fatalf("reply %x", got)
	}
	for i := 4; i < 22; i++ {
		if got[i] != 0 {
			t.Fatalf("BND not :: :0: %x", got)
		}
	}
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", net.JoinHostPort(host, pstr)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "v6" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
}

func TestSOCKS5AdmissionFull(t *testing.T) {
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hold")
	}))
	spec := socks5Spec(t)
	spec.Proxy.Admission.MaxSessions = 1
	px := startProxy(t, Options{Spec: spec})
	ip, port, _ := ipv4Port(t, origin)
	hold := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, hold)
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, ip...)
	req = append(req, bePort(port)...)
	writeAll(t, hold, req)
	ok := readN(t, hold, 10)
	if ok[1] != 0x00 {
		t.Fatalf("first CONNECT %x", ok)
	}

	c2 := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c2)
	writeAll(t, c2, req)
	got := readN(t, c2, 10)
	if got[1] != 0x01 {
		t.Fatalf("admission rep %x want 05 01", got)
	}
	if px.Metrics().Rejected("admission") < 1 {
		t.Fatal("expected admission reject")
	}
}

func TestSOCKS5Intercept(t *testing.T) {
	var hits atomic.Int32
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "secret-socks")
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	spec.Listeners.Proxy.AcceptSOCKS5 = true
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	auth := px.Authority()
	if auth == nil {
		t.Fatal("missing lab CA")
	}

	c := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c)
	host := "app.lab"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, bePort(port)...)
	writeAll(t, c, req)
	rep := readN(t, c, 10)
	if rep[1] != 0x00 {
		t.Fatalf("CONNECT %x", rep)
	}

	tlsC := tls.Client(c, &tls.Config{
		ServerName: "app.lab",
		RootCAs:    auth.CertPool(),
		NextProtos: []string{tlsmitm.ALPN},
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsC.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tlsC, "GET /hello HTTP/1.1\r\nHost: app.lab\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsC), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "secret-socks" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if hits.Load() != 1 {
		t.Fatalf("origin hits %d", hits.Load())
	}
	if px.Metrics().TLSIntercepts(tlsmitm.ResultOK) < 1 {
		t.Fatal("missing tls intercept ok")
	}
	found := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range sink.Last() {
			if f.Intercepted && f.Via == "socks5" && f.SOCKS != nil && strings.Contains(f.URL, "/hello") {
				found = true
			}
		}
		if found {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !found {
		t.Fatalf("no intercepted socks flow: %+v", sink.Last())
	}
}

func TestSOCKS5InterceptRequestBreakpointStampsVia(t *testing.T) {
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "after")
	}))
	_, port := hostPort(t, origin)
	spec := interceptSpec(t, port, testdataTLS(t, "origin-ca.pem"))
	spec.Listeners.Proxy.AcceptSOCKS5 = true
	spec.Rules = model.RulesSpec{
		Enabled: true,
		Items: []model.RuleSpec{{
			ID:      "brk",
			Enabled: true,
			Phase:   model.RulePhaseRequest,
			Match:   model.RuleMatchSpec{PathPrefix: "/hello"},
			Action:  model.RuleActionSpec{Type: model.ActionBreakpoint, Breakpoint: model.RuleBreakpointSpec{Timeout: 5 * time.Second}},
		}},
	}
	inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: time.Minute})
	px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Store: inbox, Resolver: appLabResolver()})
	auth := px.Authority()
	if auth == nil {
		t.Fatal("missing lab CA")
	}

	done := make(chan error, 1)
	go func() {
		c, err := net.DialTimeout("tcp", px.Addr().String(), 2*time.Second)
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))
		if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			done <- err
			return
		}
		greet := make([]byte, 2)
		if _, err := io.ReadFull(c, greet); err != nil {
			done <- err
			return
		}
		if greet[0] != 0x05 || greet[1] != 0x00 {
			done <- fmt.Errorf("greeting %x", greet)
			return
		}
		host := "app.lab"
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, host...)
		req = append(req, bePort(port)...)
		if _, err := c.Write(req); err != nil {
			done <- err
			return
		}
		rep := make([]byte, 10)
		if _, err := io.ReadFull(c, rep); err != nil {
			done <- err
			return
		}
		if rep[1] != 0x00 {
			done <- fmt.Errorf("CONNECT %x", rep)
			return
		}
		tlsC := tls.Client(c, &tls.Config{
			ServerName: "app.lab",
			RootCAs:    auth.CertPool(),
			NextProtos: []string{tlsmitm.ALPN},
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsC.Handshake(); err != nil {
			done <- err
			return
		}
		if _, err := io.WriteString(tlsC, "GET /hello HTTP/1.1\r\nHost: app.lab\r\n\r\n"); err != nil {
			done <- err
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(tlsC), nil)
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(body) != "after" {
			done <- fmt.Errorf("status %d body %q", resp.StatusCode, body)
			return
		}
		done <- nil
	}()

	paused := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/hello"})
	if paused.State != model.FlowStatePaused {
		t.Fatalf("state %q", paused.State)
	}
	if paused.Via != "socks5" || paused.SOCKS == nil || paused.SOCKS.Version != 5 {
		t.Fatalf("paused Via/SOCKS %+v SOCKS=%+v", paused.Via, paused.SOCKS)
	}
	if err := inbox.Resume(paused.ID, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client hung")
	}
}

func TestSOCKS4Connect(t *testing.T) {
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "s4")
	}))
	sink := NewNull()
	px := startProxy(t, Options{Spec: socks4Spec(t), Sink: sink})
	ip, port, host := ipv4Port(t, origin)
	c := socksDial(t, px.Addr().String())
	req := []byte{0x04, 0x01}
	req = append(req, bePort(port)...)
	req = append(req, ip...)
	req = append(req, 0) // empty userid
	writeAll(t, c, req)
	got := readN(t, c, 8)
	if got[0] != 0 || got[1] != 90 {
		t.Fatalf("socks4 reply %x", got)
	}
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "s4" {
		t.Fatalf("body %q", body)
	}
	found := false
	for _, f := range sink.Last() {
		if f.Protocol == model.FlowProtocolSOCKS4 && f.Via == "socks4" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing socks4 flow %+v", sink.Last())
	}
}

func TestSOCKS4aDomain(t *testing.T) {
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "s4a")
	}))
	_, pstr, err := net.SplitHostPort(origin)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(pstr)
	if err != nil {
		t.Fatal(err)
	}
	px := startProxy(t, Options{
		Spec:     socks4Spec(t),
		Resolver: mapResolver{"app.lab": {net.ParseIP("127.0.0.1")}},
	})
	c := socksDial(t, px.Addr().String())
	req := []byte{0x04, 0x01}
	req = append(req, bePort(port)...)
	req = append(req, 0, 0, 0, 1) // 4a
	req = append(req, 0)          // userid
	req = append(req, []byte("app.lab")...)
	req = append(req, 0)
	writeAll(t, c, req)
	got := readN(t, c, 8)
	if got[1] != 90 {
		t.Fatalf("socks4a reply %x", got)
	}
}

func TestSOCKS4CommandRejected(t *testing.T) {
	// acceptSOCKS4 on, acceptBind off (D58): CD=2 stays 91.
	px := startProxy(t, Options{Spec: socks4Spec(t)})
	c := socksDial(t, px.Addr().String())
	writeAll(t, c, []byte{0x04, 0x02, 0, 80, 127, 0, 0, 1, 0})
	got := readN(t, c, 8)
	if got[1] != 91 {
		t.Fatalf("got %x want CD=91", got)
	}
}

func TestSOCKS5BindSuccess(t *testing.T) {
	recL := &recordingListen{}
	sink := NewNull()
	px := startProxy(t, Options{
		Spec:      socks5BindSpec(t),
		Sink:      sink,
		ListenTCP: recL.wrap(listenEphemeralTCP),
	})
	c := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c)
	req := append([]byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1}, bePort(80)...)
	writeAll(t, c, req)
	got := readN(t, c, 10)
	if got[0] != 0x05 || got[1] != 0x00 || got[3] != 0x01 {
		t.Fatalf("first reply %x", got)
	}
	ip := net.IP(got[4:8])
	port := int(binary.BigEndian.Uint16(got[8:10]))
	if ip.IsUnspecified() || port == 0 {
		t.Fatalf("BND unspecified %v:%d", ip, port)
	}
	bnd := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	if bnd == px.Addr().String() {
		t.Fatal("BND must not be listeners.proxy.address")
	}
	listened := recL.Addrs()
	if len(listened) != 1 || net.ParseIP(listened[0]).IsUnspecified() {
		t.Fatalf("listen %v", listened)
	}
	peer, err := net.DialTimeout("tcp", bnd, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	got2 := readN(t, c, 10)
	if got2[1] != 0x00 {
		t.Fatalf("second reply %x", got2)
	}
	writeAll(t, c, []byte("ping"))
	if string(readN(t, peer, 4)) != "ping" {
		t.Fatal("client→peer")
	}
	writeAll(t, peer, []byte("pong"))
	if string(readN(t, c, 4)) != "pong" {
		t.Fatal("peer→client")
	}
	found := false
	for _, f := range sink.Last() {
		if f.SOCKS != nil && f.SOCKS.Command == model.SOCKSCmdBind {
			found = true
			if f.Protocol != model.FlowProtocolSOCKS5 || f.Intercepted {
				t.Fatalf("flow %+v", f)
			}
			if f.SOCKS.BND != bnd {
				t.Fatalf("BND %q want %q", f.SOCKS.BND, bnd)
			}
		}
	}
	if !found {
		t.Fatalf("missing bind flow: %+v", sink.Last())
	}
	if px.Metrics().Socks("ok") < 1 {
		t.Fatal("expected socks ok")
	}
}

func TestSOCKS5BindIMDSDoesNotListen(t *testing.T) {
	recL := &recordingListen{}
	recD := &recordingDial{}
	px := startProxy(t, Options{
		Spec:        socks5BindSpec(t),
		ListenTCP:   recL.wrap(nil),
		DialContext: recD.wrap(nil),
	})
	c := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c)
	req := append([]byte{0x05, 0x02, 0x00, 0x01, 169, 254, 169, 254}, bePort(80)...)
	writeAll(t, c, req)
	got := readN(t, c, 10)
	if got[1] != 0x02 {
		t.Fatalf("imds bind %x want 05 02", got)
	}
	if len(recL.Addrs()) != 0 {
		t.Fatalf("listened %v", recL.Addrs())
	}
	if len(recD.Addrs()) != 0 {
		t.Fatalf("dialed %v", recD.Addrs())
	}
}

func TestSOCKS5BindUnspecifiedDoesNotListen(t *testing.T) {
	recL := &recordingListen{}
	px := startProxy(t, Options{
		Spec:      socks5BindSpec(t),
		ListenTCP: recL.wrap(nil),
	})
	c := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c)
	writeAll(t, c, []byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	got := readN(t, c, 10)
	if got[1] != 0x02 {
		t.Fatalf("unspecified bind %x want 05 02", got)
	}
	if len(recL.Addrs()) != 0 {
		t.Fatalf("listened %v", recL.Addrs())
	}

	c6 := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c6)
	req6 := []byte{0x05, 0x02, 0x00, 0x04}
	req6 = append(req6, make([]byte, 16)...)
	req6 = append(req6, 0, 0)
	writeAll(t, c6, req6)
	got6 := readN(t, c6, 22)
	if got6[1] != 0x02 {
		t.Fatalf("unspecified v6 bind %x want 05 02", got6)
	}
	if len(recL.Addrs()) != 0 {
		t.Fatalf("listened after v6 %v", recL.Addrs())
	}
}

func TestSOCKS5BindHairpinBND(t *testing.T) {
	recD := &recordingDial{}
	px := startProxy(t, Options{
		Spec:        socks5BindSpec(t),
		DialContext: recD.wrap(nil),
	})
	c := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c)
	req := append([]byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1}, bePort(80)...)
	writeAll(t, c, req)
	got := readN(t, c, 10)
	if got[1] != 0x00 {
		t.Fatalf("first reply %x", got)
	}
	ip := net.IP(got[4:8])
	port := int(binary.BigEndian.Uint16(got[8:10]))
	c2 := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c2)
	creq := append([]byte{0x05, 0x01, 0x00, 0x01}, ip.To4()...)
	creq = append(creq, bePort(port)...)
	writeAll(t, c2, creq)
	got2 := readN(t, c2, 10)
	if got2[1] != 0x02 {
		t.Fatalf("hairpin CONNECT %x want 05 02", got2)
	}
	if len(recD.Addrs()) != 0 {
		t.Fatalf("hairpin dialed %v", recD.Addrs())
	}
}

func TestSOCKS5BindWrongPeer(t *testing.T) {
	// DST resolves to 10.0.0.1; inbound Accept from 127.0.0.1 must fail (K5 step 7).
	sink := NewNull()
	px := startProxy(t, Options{
		Spec:     socks5BindSpec(t),
		Sink:     sink,
		Resolver: mapResolver{"peer.lab": {net.ParseIP("10.0.0.1")}},
	})
	c := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c)
	host := "peer.lab"
	req := []byte{0x05, 0x02, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, bePort(80)...)
	writeAll(t, c, req)
	got := readN(t, c, 10)
	if got[1] != 0x00 {
		t.Fatalf("first reply %x", got)
	}
	ip := net.IP(got[4:8])
	port := int(binary.BigEndian.Uint16(got[8:10]))
	bnd := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	peer, err := net.DialTimeout("tcp", bnd, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	got2 := readN(t, c, 10)
	if got2[1] != 0x02 {
		t.Fatalf("wrong peer %x want 05 02", got2)
	}
	_ = peer.SetDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = c.Write([]byte("ping")) // control may already be closing
	buf := make([]byte, 4)
	n, rerr := peer.Read(buf)
	if n > 0 {
		t.Fatalf("tunneled %q", buf[:n])
	}
	if rerr == nil {
		t.Fatal("expected peer close, no tunnel")
	}
	found := false
	for _, f := range sink.Last() {
		if f.SOCKS != nil && f.SOCKS.Command == model.SOCKSCmdBind {
			found = true
			if f.Error != "target_denied" || f.Intercepted {
				t.Fatalf("flow %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("missing bind flow: %+v", sink.Last())
	}
	if px.Metrics().Rejected("target_denied") < 1 || px.Metrics().Socks("denied") < 1 {
		t.Fatal("expected target_denied")
	}
	if px.Metrics().Socks("ok") != 0 {
		t.Fatal("wrong peer must not count socks ok")
	}
}

func TestSOCKS4Bind(t *testing.T) {
	sink := NewNull()
	px := startProxy(t, Options{Spec: socks4BindSpec(t), Sink: sink})
	c := socksDial(t, px.Addr().String())
	req := []byte{0x04, 0x02}
	req = append(req, bePort(80)...)
	req = append(req, 127, 0, 0, 1, 0)
	writeAll(t, c, req)
	got := readN(t, c, 8)
	if got[0] != 0 || got[1] != 90 {
		t.Fatalf("first reply %x", got)
	}
	port := int(binary.BigEndian.Uint16(got[2:4]))
	ip := net.IPv4(got[4], got[5], got[6], got[7])
	if ip.IsUnspecified() || port == 0 {
		t.Fatalf("BND %v:%d", ip, port)
	}
	bnd := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	if bnd == px.Addr().String() {
		t.Fatal("BND must not be listeners.proxy.address")
	}
	peer, err := net.DialTimeout("tcp", bnd, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	got2 := readN(t, c, 8)
	if got2[1] != 90 {
		t.Fatalf("second reply %x", got2)
	}
	writeAll(t, c, []byte("s4"))
	if string(readN(t, peer, 2)) != "s4" {
		t.Fatal("client→peer")
	}
	found := false
	for _, f := range sink.Last() {
		if f.Protocol == model.FlowProtocolSOCKS4 && f.SOCKS != nil && f.SOCKS.Command == model.SOCKSCmdBind {
			found = true
			if f.Intercepted {
				t.Fatal("bind must not intercept")
			}
		}
	}
	if !found {
		t.Fatalf("missing socks4 bind flow %+v", sink.Last())
	}
}

func TestListenEphemeralTCPRejectsUnspecified(t *testing.T) {
	if _, err := listenEphemeralTCP(net.IPv4zero); err == nil {
		t.Fatal("expected reject 0.0.0.0")
	}
	if _, err := listenEphemeralTCP(net.IPv6unspecified); err == nil {
		t.Fatal("expected reject ::")
	}
	if _, err := listenEphemeralTCP(net.ParseIP("169.254.169.254")); err == nil {
		t.Fatal("expected reject IMDS")
	}
	if _, err := listenEphemeralTCP(net.ParseIP("fe80::1")); err == nil {
		t.Fatal("expected reject link-local")
	}
}

func TestListenEphemeralUDPRejectsUnspecified(t *testing.T) {
	if _, err := listenEphemeralUDP(net.IPv4zero); err == nil {
		t.Fatal("expected reject 0.0.0.0")
	}
	if _, err := listenEphemeralUDP(net.IPv6unspecified); err == nil {
		t.Fatal("expected reject ::")
	}
	if _, err := listenEphemeralUDP(net.ParseIP("169.254.169.254")); err == nil {
		t.Fatal("expected reject IMDS")
	}
	if _, err := listenEphemeralUDP(net.ParseIP("fe80::1")); err == nil {
		t.Fatal("expected reject link-local")
	}
}

func TestDialUDPRefusesHostname(t *testing.T) {
	_, err := dialUDP(t.Context(), "udp", "example.lab:9", time.Second)
	if err == nil {
		t.Fatal("expected refuse hostname")
	}
}

func TestSOCKS5NameIMDSDoesNotDial(t *testing.T) {
	rec := &recordingDial{}
	px := startProxy(t, Options{
		Spec:        socks5Spec(t),
		Resolver:    mapResolver{"metadata.google.internal": {net.ParseIP("169.254.169.254")}},
		DialContext: rec.wrap(nil),
	})
	c := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c)
	host := "metadata.google.internal"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, 0, 80)
	writeAll(t, c, req)
	got := readN(t, c, 10)
	if got[1] != 0x02 {
		t.Fatalf("imds name rep %x", got)
	}
	if len(rec.Addrs()) != 0 {
		t.Fatalf("dialed %v", rec.Addrs())
	}
}

func mustHost(t *testing.T, originURL string) string {
	t.Helper()
	u := strings.TrimPrefix(originURL, "http://")
	u = strings.TrimPrefix(u, "https://")
	if i := strings.IndexByte(u, '/'); i >= 0 {
		u = u[:i]
	}
	return u
}

func playSOCKSTranscript(t *testing.T, addr, path string, vars map[string]string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	expand := func(s string) string {
		for k, v := range vars {
			s = strings.ReplaceAll(s, "{{"+k+"}}", v)
		}
		return s
	}
	lines := strings.Split(string(raw), "\n")
	i := 0
	for i < len(lines) {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			i++
			continue
		}
		switch {
		case strings.HasPrefix(line, "C-HEX:"):
			b, err := parseHex(expand(strings.TrimSpace(strings.TrimPrefix(line, "C-HEX:"))))
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			if _, err := c.Write(b); err != nil {
				t.Fatalf("%s: write: %v", path, err)
			}
			i++
		case strings.HasPrefix(line, "S-HEX:"):
			want, err := parseHex(expand(strings.TrimSpace(strings.TrimPrefix(line, "S-HEX:"))))
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			got := make([]byte, len(want))
			if _, err := io.ReadFull(br, got); err != nil {
				t.Fatalf("%s: read: %v want %x", path, err, want)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s: got %x want %x", path, got, want)
			}
			i++
		case line == "S-CLOSE":
			buf := make([]byte, 8)
			n, err := br.Read(buf)
			if err == nil && n > 0 {
				t.Fatalf("%s: got %x want close", path, buf[:n])
			}
			if err == nil {
				t.Fatalf("%s: expected close", path)
			}
			i++
		case strings.HasPrefix(line, "C:"):
			var raww strings.Builder
			for i < len(lines) {
				l := strings.TrimSpace(lines[i])
				if l == "" || strings.HasPrefix(l, "#") {
					i++
					continue
				}
				if !strings.HasPrefix(l, "C:") || strings.HasPrefix(l, "C-HEX:") {
					break
				}
				text := ""
				if len(l) > 2 {
					text = strings.TrimSpace(l[2:])
				}
				raww.WriteString(expand(text))
				raww.WriteString("\r\n")
				i++
			}
			if _, err := c.Write([]byte(raww.String())); err != nil {
				t.Fatalf("%s: write: %v", path, err)
			}
		case strings.HasPrefix(line, "S:"):
			want := expand(strings.TrimSpace(strings.TrimPrefix(line, "S:")))
			got, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("%s: read: %v want %q", path, err, want)
			}
			got = strings.TrimRight(got, "\r\n")
			if strings.HasSuffix(want, "*") {
				if !strings.HasPrefix(got, strings.TrimSuffix(want, "*")) {
					t.Fatalf("%s: got %q want %q", path, got, want)
				}
			} else if got != want {
				t.Fatalf("%s: got %q want %q", path, got, want)
			}
			i++
		default:
			t.Fatalf("%s: bad line %q", path, line)
		}
	}
}

func parseHex(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex %q", s)
	}
	return hex.DecodeString(s)
}

func startUDPEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], from)
		}
	}()
	return pc
}

func listenUDPClient(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	return pc
}

func socksUDP4(ip net.IP, port int, data []byte) []byte {
	p := []byte{0, 0, 0, socks5ATYPIPv4}
	p = append(p, ip.To4()...)
	p = append(p, bePort(port)...)
	return append(p, data...)
}

func socksUDPDomain(host string, port int, data []byte) []byte {
	p := []byte{0, 0, 0, socks5ATYPDomain, byte(len(host))}
	p = append(p, host...)
	p = append(p, bePort(port)...)
	return append(p, data...)
}

func writeUDPTo(t *testing.T, c *net.UDPConn, bnd string, pkt []byte) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", bnd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteToUDP(pkt, addr); err != nil {
		t.Fatal(err)
	}
}

func readUDPFrom(t *testing.T, c *net.UDPConn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func socks5Associate(t *testing.T, px *Server) (control net.Conn, bnd string, ip net.IP, port int) {
	t.Helper()
	c := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c)
	writeAll(t, c, []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	got := readN(t, c, 10)
	if got[0] != 0x05 || got[1] != 0x00 || got[3] != 0x01 {
		t.Fatalf("associate %x", got)
	}
	ip = net.IP(got[4:8])
	port = int(binary.BigEndian.Uint16(got[8:10]))
	if ip.IsUnspecified() || port == 0 {
		t.Fatalf("BND unspecified %v:%d", ip, port)
	}
	bnd = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	if bnd == px.Addr().String() {
		t.Fatal("BND must not be listeners.proxy.address")
	}
	return c, bnd, ip, port
}

func waitUDPFlow(t *testing.T, sink *Null) *model.Flow {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range sink.Last() {
			if f.SOCKS != nil && f.SOCKS.Command == model.SOCKSCmdUDP {
				return f
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("missing udp flow: %+v", sink.Last())
	return nil
}

func TestSOCKS5UDPAssociateEcho(t *testing.T) {
	origin := startUDPEcho(t)
	_, oPort, _ := ipv4Port(t, origin.LocalAddr().String())
	oIP := net.ParseIP("127.0.0.1").To4()
	sink := NewNull()
	recU := &recordingUDP{}
	px := startProxy(t, Options{
		Spec:      socks5UDPSpec(t),
		Sink:      sink,
		ListenUDP: recU.wrap(listenEphemeralUDP),
	})
	control, bnd, _, _ := socks5Associate(t, px)
	listened := recU.Addrs()
	if len(listened) != 1 || net.ParseIP(listened[0]).IsUnspecified() {
		t.Fatalf("listen %v", listened)
	}
	cli := listenUDPClient(t)
	writeUDPTo(t, cli, bnd, socksUDP4(oIP, oPort, []byte("ping")))
	got := readUDPFrom(t, cli)
	host, port, data, ok := parseSOCKSUDP(got)
	if !ok || string(data) != "ping" {
		t.Fatalf("echo %x host=%s port=%s data=%q", got, host, port, data)
	}
	_ = control.Close()
	f := waitUDPFlow(t, sink)
	if f.Protocol != model.FlowProtocolSOCKS5 || f.Intercepted || f.Method != http.MethodConnect {
		t.Fatalf("flow %+v", f)
	}
	if f.SOCKS.Datagrams < 2 || f.SOCKS.LastDest == "" || f.SOCKS.BND != bnd {
		t.Fatalf("SOCKS %+v", f.SOCKS)
	}
	if px.Metrics().Socks("ok") < 1 {
		t.Fatal("expected socks ok")
	}
}

func TestSOCKS5UDPUnspecifiedDST(t *testing.T) {
	// ASSOCIATE DST 0.0.0.0:0 is legal (unlike BIND).
	px := startProxy(t, Options{Spec: socks5UDPSpec(t)})
	_, bnd, _, _ := socks5Associate(t, px)
	if bnd == "" {
		t.Fatal("empty BND")
	}
}

func TestSOCKS5UDPFirstDatagramPinsClient(t *testing.T) {
	var originN atomic.Int64
	origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, rerr := origin.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			originN.Add(1)
			_, _ = origin.WriteToUDP(buf[:n], from)
		}
	}()
	_, oPort, _ := ipv4Port(t, origin.LocalAddr().String())
	oIP := net.ParseIP("127.0.0.1").To4()
	px := startProxy(t, Options{Spec: socks5UDPSpec(t)})
	control, bnd, _, _ := socks5Associate(t, px)
	cli1 := listenUDPClient(t)
	cli2 := listenUDPClient(t)
	writeUDPTo(t, cli1, bnd, socksUDP4(oIP, oPort, []byte("a")))
	_ = readUDPFrom(t, cli1)
	if originN.Load() != 1 {
		t.Fatalf("origin got %d want 1", originN.Load())
	}
	writeUDPTo(t, cli2, bnd, socksUDP4(oIP, oPort, []byte("b")))
	_ = cli2.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 64)
	if n, _, rerr := cli2.ReadFromUDP(buf); n > 0 {
		t.Fatalf("second source tunneled %q", buf[:n])
	} else if rerr == nil {
		t.Fatal("expected timeout on second source")
	}
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) && originN.Load() == 1 {
		time.Sleep(5 * time.Millisecond)
	}
	if originN.Load() != 1 {
		t.Fatalf("second source reached origin (%d)", originN.Load())
	}
	writeUDPTo(t, cli1, bnd, socksUDP4(oIP, oPort, []byte("c")))
	got := readUDPFrom(t, cli1)
	_, _, data, ok := parseSOCKSUDP(got)
	if !ok || string(data) != "c" {
		t.Fatalf("pinned client echo %q", data)
	}
	_ = control.Close()
}

func TestSOCKS5UDPDomainPin(t *testing.T) {
	origin := startUDPEcho(t)
	_, oPort, _ := ipv4Port(t, origin.LocalAddr().String())
	res := &countingResolver{inner: mapResolver{"echo.lab": {net.ParseIP("127.0.0.1")}}}
	px := startProxy(t, Options{Spec: socks5UDPSpec(t), Resolver: res})
	control, bnd, _, _ := socks5Associate(t, px)
	cli := listenUDPClient(t)
	writeUDPTo(t, cli, bnd, socksUDPDomain("echo.lab", oPort, []byte("one")))
	_ = readUDPFrom(t, cli)
	writeUDPTo(t, cli, bnd, socksUDPDomain("echo.lab", oPort, []byte("two")))
	_ = readUDPFrom(t, cli)
	if res.n.Load() != 1 {
		t.Fatalf("LookupIP %d want 1", res.n.Load())
	}
	_ = control.Close()
}

func TestSOCKS5UDPIMDSDropped(t *testing.T) {
	recU := &recordingUDP{}
	px := startProxy(t, Options{
		Spec:      socks5UDPSpec(t),
		ListenUDP: recU.wrap(listenEphemeralUDP),
	})
	control, bnd, _, _ := socks5Associate(t, px)
	cli := listenUDPClient(t)
	imds := net.ParseIP("169.254.169.254").To4()
	writeUDPTo(t, cli, bnd, socksUDP4(imds, 80, []byte("x")))
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("target_denied") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("target_denied") < 1 {
		t.Fatal("expected target_denied")
	}
	for _, w := range recU.Writes() {
		if strings.HasPrefix(w, "169.254.169.254:") {
			t.Fatalf("wrote IMDS %v", recU.Writes())
		}
	}
	_ = control.Close()
}

func TestSOCKS5UDPFRAGDropped(t *testing.T) {
	var originN atomic.Int64
	origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			_, _, rerr := origin.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			originN.Add(1)
		}
	}()
	_, oPort, _ := ipv4Port(t, origin.LocalAddr().String())
	oIP := net.ParseIP("127.0.0.1").To4()
	px := startProxy(t, Options{Spec: socks5UDPSpec(t)})
	control, bnd, _, _ := socks5Associate(t, px)
	cli := listenUDPClient(t)
	pkt := socksUDP4(oIP, oPort, []byte("frag"))
	pkt[2] = 1
	writeUDPTo(t, cli, bnd, pkt)
	time.Sleep(100 * time.Millisecond)
	if originN.Load() != 0 {
		t.Fatalf("FRAG reached origin (%d)", originN.Load())
	}
	_ = control.Close()
}

func TestSOCKS5UDPHairpinDropped(t *testing.T) {
	recU := &recordingUDP{}
	px := startProxy(t, Options{
		Spec:      socks5UDPSpec(t),
		ListenUDP: recU.wrap(listenEphemeralUDP),
	})
	control, bnd, ip, port := socks5Associate(t, px)
	cli := listenUDPClient(t)
	writeUDPTo(t, cli, bnd, socksUDP4(ip.To4(), port, []byte("loop")))
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("target_denied") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("target_denied") < 1 {
		t.Fatal("expected hairpin target_denied")
	}
	_ = control.Close()
}

func TestSOCKS5UDPInboundCap(t *testing.T) {
	origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	_, oPort, _ := ipv4Port(t, origin.LocalAddr().String())
	oIP := net.ParseIP("127.0.0.1").To4()
	spec := socks5UDPSpec(t)
	spec.Proxy.Admission.MaxInFlightBytes = 80
	sink := NewNull()
	px := startProxy(t, Options{Spec: spec, Sink: sink})
	control, bnd, _, _ := socks5Associate(t, px)
	cli := listenUDPClient(t)
	_ = origin.SetReadDeadline(time.Now().Add(2 * time.Second))
	writeUDPTo(t, cli, bnd, socksUDP4(oIP, oPort, []byte("pin")))
	_, from, err := origin.ReadFromUDP(make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 50)
	if _, err := origin.WriteToUDP(payload, from); err != nil {
		t.Fatal(err)
	}
	got := readUDPFrom(t, cli)
	_, _, data, ok := parseSOCKSUDP(got)
	if !ok || len(data) != 50 {
		t.Fatalf("first inbound %d ok=%v", len(data), ok)
	}
	if _, err := origin.WriteToUDP(payload, from); err != nil {
		t.Fatal(err)
	}
	if _, err := origin.WriteToUDP(payload, from); err != nil {
		t.Fatal(err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	extra := 0
	buf := make([]byte, 256)
	for {
		n, _, rerr := cli.ReadFromUDP(buf)
		if rerr != nil {
			break
		}
		if n > 0 {
			extra++
		}
	}
	if extra != 0 {
		t.Fatalf("over-cap inbound delivered %d", extra)
	}
	_ = control.Close()
	f := waitUDPFlow(t, sink)
	if !f.Truncated {
		t.Fatalf("want Truncated flow %+v", f)
	}
}

func TestSOCKS5UDPIdleTimeout(t *testing.T) {
	origin := startUDPEcho(t)
	_, oPort, _ := ipv4Port(t, origin.LocalAddr().String())
	oIP := net.ParseIP("127.0.0.1").To4()
	spec := socks5UDPSpec(t)
	spec.Proxy.Admission.IdleTimeout = 150 * time.Millisecond
	spec.Proxy.Admission.SessionTimeout = time.Minute
	sink := NewNull()
	px := startProxy(t, Options{Spec: spec, Sink: sink})
	control, bnd, _, _ := socks5Associate(t, px)
	_ = waitUDPFlow(t, sink)
	cli := listenUDPClient(t)
	writeUDPTo(t, cli, bnd, socksUDP4(oIP, oPort, []byte("late")))
	_ = cli.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 64)
	n, _, err := cli.ReadFromUDP(buf)
	if n > 0 {
		t.Fatalf("relayed after idle %q", buf[:n])
	}
	if err == nil {
		t.Fatal("expected no reply after idle")
	}
	_ = control.Close()
}

func TestSOCKS5UDPControlCloseTearsDown(t *testing.T) {
	origin := startUDPEcho(t)
	_, oPort, _ := ipv4Port(t, origin.LocalAddr().String())
	oIP := net.ParseIP("127.0.0.1").To4()
	sink := NewNull()
	px := startProxy(t, Options{Spec: socks5UDPSpec(t), Sink: sink})
	control, bnd, _, _ := socks5Associate(t, px)
	cli := listenUDPClient(t)
	writeUDPTo(t, cli, bnd, socksUDP4(oIP, oPort, []byte("open")))
	_ = readUDPFrom(t, cli)
	_ = control.Close()
	_ = waitUDPFlow(t, sink)
	writeUDPTo(t, cli, bnd, socksUDP4(oIP, oPort, []byte("after")))
	_ = cli.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 64)
	n, _, err := cli.ReadFromUDP(buf)
	if n > 0 {
		t.Fatalf("relayed after control close %q", buf[:n])
	}
	if err == nil {
		t.Fatal("expected no reply after control close")
	}
}

func TestSOCKS5NMethodsZeroCloses(t *testing.T) {
	px := startProxy(t, Options{Spec: socks5Spec(t)})
	c := socksDial(t, px.Addr().String())
	writeAll(t, c, []byte{0x05, 0x00})
	buf := make([]byte, 8)
	n, err := c.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("got %x want close", buf[:n])
	}
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("socks_auth") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("socks_auth") < 1 {
		t.Fatal("expected socks_auth")
	}
}

func userPassSpec(t *testing.T) model.Spec {
	t.Helper()
	spec := socks5Spec(t)
	spec.Listeners.Proxy.AcceptUserPass = true
	spec.Listeners.Proxy.UserPass.Users = []model.UserPassUserSpec{{
		ID:           "lab-socks",
		UsernameFile: filepath.Join(moduleRoot(t), "testdata", "config", "valid", "socks-username"),
		PasswordFile: filepath.Join(moduleRoot(t), "testdata", "config", "valid", "socks-password"),
	}}
	return spec
}

func startUserPassProxy(t *testing.T, opts Options) *Server {
	t.Helper()
	if opts.Spec.Listeners.Proxy.Address == "" {
		opts.Spec = userPassSpec(t)
	}
	st := &model.State{
		APIVersion: model.APIVersionV1Alpha1,
		Kind:       model.KindLabMITM,
		Metadata:   model.Metadata{Name: "t"},
		Spec:       opts.Spec,
	}
	snap, err := compiler.Compile(t.Context(), st, compiler.CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	snaps := snapshot.NewStore()
	snaps.InstallBootstrap(snap)
	opts.Spec = snap.Canonical.Spec
	opts.Snapshots = snaps
	if opts.Authority == nil {
		opts.Authority = snap.CA
	}
	return startProxy(t, opts)
}

func socks5UserPassAuth(t *testing.T, c net.Conn, user, pass string) []byte {
	t.Helper()
	req := []byte{0x01, byte(len(user))}
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	writeAll(t, c, req)
	return readN(t, c, 2)
}

func TestSOCKS5UserPassWrongPassword(t *testing.T) {
	var logBuf bytes.Buffer
	px := startUserPassProxy(t, Options{Logger: observability.NewLogger(&logBuf, observability.LevelDebug).WithSync()})
	c := socksDial(t, px.Addr().String())
	writeAll(t, c, []byte{0x05, 0x01, 0x02})
	got := readN(t, c, 2)
	if got[0] != 0x05 || got[1] != 0x02 {
		t.Fatalf("greeting %x want 05 02", got)
	}
	rep := socks5UserPassAuth(t, c, "labuser", "wrongpass")
	if rep[0] != 0x01 || rep[1] != 0x01 {
		t.Fatalf("auth reply %x want 01 01", rep)
	}
	buf := make([]byte, 8)
	n, err := c.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("got %x want close", buf[:n])
	}
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("socks_auth") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("socks_auth") < 1 || px.Metrics().Socks("auth") < 1 {
		t.Fatal("expected socks_auth")
	}
	logged := logBuf.String()
	if strings.Contains(logged, "labpass12") || strings.Contains(logged, "wrongpass") || strings.Contains(logged, "labuser") {
		t.Fatalf("log leaked SOCKS secret: %s", logged)
	}
}

func TestSOCKS5UserPassMissingMethodEvenIfNoAuthOffered(t *testing.T) {
	px := startUserPassProxy(t, Options{})
	c := socksDial(t, px.Addr().String())
	writeAll(t, c, []byte{0x05, 0x01, 0x00})
	got := readN(t, c, 2)
	if got[0] != 0x05 || got[1] != 0xff {
		t.Fatalf("got %x want 05 ff", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for px.Metrics().Rejected("socks_auth") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if px.Metrics().Rejected("socks_auth") < 1 {
		t.Fatal("expected socks_auth")
	}
}

func TestSOCKS5UserPassOffStillNoAuth(t *testing.T) {
	px := startProxy(t, Options{Spec: socks5Spec(t)})
	c := socksDial(t, px.Addr().String())
	writeAll(t, c, []byte{0x05, 0x02, 0x02, 0x00})
	got := readN(t, c, 2)
	if got[0] != 0x05 || got[1] != 0x00 {
		t.Fatalf("got %x want 05 00", got)
	}
}

func TestSOCKS5GSSAPINeverSelected(t *testing.T) {
	t.Run("flag-off", func(t *testing.T) {
		px := startProxy(t, Options{Spec: socks5Spec(t)})
		c := socksDial(t, px.Addr().String())
		writeAll(t, c, []byte{0x05, 0x01, 0x01})
		got := readN(t, c, 2)
		if got[0] != 0x05 || got[1] != 0xff {
			t.Fatalf("got %x want 05 ff", got)
		}
	})
	t.Run("flag-on", func(t *testing.T) {
		px := startUserPassProxy(t, Options{})
		c := socksDial(t, px.Addr().String())
		writeAll(t, c, []byte{0x05, 0x02, 0x01, 0x00})
		got := readN(t, c, 2)
		if got[0] != 0x05 || got[1] != 0xff {
			t.Fatalf("got %x want 05 ff even if 0x00 offered", got)
		}
	})
}

func TestSOCKS5UserPassSuccessStampsYAMLID(t *testing.T) {
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "socks-up")
	}))
	sink := NewNull()
	px := startUserPassProxy(t, Options{Sink: sink})
	ip, port, host := ipv4Port(t, origin)
	c := socksDial(t, px.Addr().String())
	writeAll(t, c, []byte{0x05, 0x01, 0x02})
	greet := readN(t, c, 2)
	if greet[0] != 0x05 || greet[1] != 0x02 {
		t.Fatalf("greeting %x", greet)
	}
	rep := socks5UserPassAuth(t, c, "labuser", "labpass12")
	if rep[0] != 0x01 || rep[1] != 0x00 {
		t.Fatalf("auth %x want 01 00", rep)
	}
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, ip...)
	req = append(req, bePort(port)...)
	writeAll(t, c, req)
	ok := readN(t, c, 10)
	if ok[1] != 0x00 {
		t.Fatalf("CONNECT %x", ok)
	}
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "socks-up" {
		t.Fatalf("body %q", body)
	}
	found := false
	for _, f := range sink.Last() {
		if f.Protocol == model.FlowProtocolSOCKS5 && f.SOCKS != nil {
			found = true
			if f.SOCKS.User != "lab-socks" {
				t.Fatalf("User=%q want lab-socks", f.SOCKS.User)
			}
			if f.SOCKS.User == "labuser" || strings.Contains(f.Error, "labpass12") {
				t.Fatalf("flow leaked credentials: %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("missing socks5 flow: %+v", sink.Last())
	}
}

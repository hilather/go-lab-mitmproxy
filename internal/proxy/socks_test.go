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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
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
	px := startProxy(t, Options{Spec: socks5Spec(t)})
	c := socksDial(t, px.Addr().String())
	socks5GreetingOK(t, c)
	writeAll(t, c, []byte{0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 80})
	got := readN(t, c, 10)
	if got[1] != 0x07 {
		t.Fatalf("udp rep %x", got)
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
	for _, f := range sink.Last() {
		if f.Intercepted && f.Via == "socks5" && f.SOCKS != nil && strings.Contains(f.URL, "/hello") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no intercepted socks flow: %+v", sink.Last())
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
	px := startProxy(t, Options{Spec: socks4Spec(t)})
	c := socksDial(t, px.Addr().String())
	writeAll(t, c, []byte{0x04, 0x02, 0, 80, 127, 0, 0, 1, 0})
	got := readN(t, c, 8)
	if got[1] != 91 {
		t.Fatalf("got %x want CD=91", got)
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

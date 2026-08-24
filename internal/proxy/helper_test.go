package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/http2x"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm"
	"golang.org/x/net/http2"
)

func testdataProxy(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(moduleRoot(t), "testdata", "proxy", name)
}

func testdataTLS(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(moduleRoot(t), "testdata", "tls", name)
}

func originCert(t *testing.T) tls.Certificate {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(testdataTLS(t, "origin.pem"), testdataTLS(t, "origin-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func startTLSOrigin(t *testing.T, cert tls.Certificate, h http.Handler) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	proto := http1Only()
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		Protocols:         proto,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	go func() { _ = srv.Serve(tlsLn) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	})
	return ln.Addr().String()
}

func startTLSOriginH2(t *testing.T, cert tls.Certificate, h http.Handler) string {
	t.Helper()
	return startTLSOriginH2State(t, cert, h, nil)
}

func startTLSOriginH2State(t *testing.T, cert tls.Certificate, h http.Handler, state func(net.Conn, http.ConnState)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{http2x.NextProtoH2, tlsmitm.ALPN},
		MinVersion:   tls.VersionTLS12,
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         cfg,
		ConnState:         state,
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, srv.TLSConfig)
	go func() { _ = srv.Serve(tlsLn) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	})
	return ln.Addr().String()
}

func hostPort(t *testing.T, addr string) (host string, port int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := net.LookupPort("tcp", p)
	if err != nil {
		t.Fatal(err)
	}
	return h, n
}

func loadSpec(t *testing.T) model.Spec {
	t.Helper()
	st, err := config.Load([]byte("apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	return st.Spec
}

func startProxy(t *testing.T, opts Options) *Server {
	t.Helper()
	if opts.Address == "" {
		opts.Address = "127.0.0.1:0"
	}
	if opts.Spec.Listeners.Proxy.Address == "" {
		opts.Spec = loadSpec(t)
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	deadline := time.Now().Add(2 * time.Second)
	for s.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.Addr() == nil {
		t.Fatal("proxy did not bind")
	}
	if opts.Spec.Listeners.OriginalDestination.Enabled {
		for s.OrigDestAddr() == nil && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if s.OrigDestAddr() == nil {
			t.Fatal("orig-dest did not bind")
		}
	}
	return s
}

func requireOrigDest(t *testing.T) {
	t.Helper()
	if !origDestSupported {
		t.Skip("originalDestination is linux-only")
	}
}

func startOrigDestProxy(t *testing.T, dest net.IP, destPort int, opts Options) *Server {
	t.Helper()
	requireOrigDest(t)
	if opts.Spec.Listeners.Proxy.Address == "" && opts.Spec.Listeners.OriginalDestination.Address == "" {
		opts.Spec = loadSpec(t)
	}
	opts.Spec.Listeners.OriginalDestination.Enabled = true
	if opts.Spec.Listeners.OriginalDestination.Address == "" && opts.OrigDestAddress == "" {
		opts.Spec.Listeners.OriginalDestination.Address = "127.0.0.1:0"
	}
	if opts.OriginalDst == nil {
		opts.OriginalDst = func(net.Conn) (net.IP, int, error) {
			return dest, destPort, nil
		}
	}
	return startProxy(t, opts)
}

func startOrigin(t *testing.T, h http.Handler) (addr, urlstr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proto := http1Only()
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		Protocols:         proto,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	})
	addr = ln.Addr().String()
	return addr, "http://" + addr
}

func startOriginOn(t *testing.T, network, bind string, h http.Handler) (addr, urlstr string) {
	t.Helper()
	ln, err := net.Listen(network, bind)
	if err != nil {
		t.Skipf("listen %s %s: %v", network, bind, err)
	}
	proto := http1Only()
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		Protocols:         proto,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	})
	addr = ln.Addr().String()
	return addr, "http://" + addr
}

type mapResolver map[string][]net.IP

func (m mapResolver) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	if addrs, ok := m[host]; ok {
		out := make([]net.IP, len(addrs))
		copy(out, addrs)
		return out, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

type countingResolver struct {
	inner Resolver
	n     atomic.Int64
}

func (c *countingResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	c.n.Add(1)
	if c.inner == nil {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return c.inner.LookupIP(ctx, network, host)
}

type recordingDial struct {
	mu    sync.Mutex
	addrs []string
}

func (r *recordingDial) wrap(inner func(ctx context.Context, network, addr string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		r.mu.Lock()
		r.addrs = append(r.addrs, addr)
		r.mu.Unlock()
		if inner != nil {
			return inner(ctx, network, addr)
		}
		return nil, io.EOF
	}
}

func (r *recordingDial) Addrs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.addrs))
	copy(out, r.addrs)
	return out
}

type recordingListen struct {
	mu    sync.Mutex
	addrs []string
}

func (r *recordingListen) wrap(inner func(net.IP) (net.Listener, error)) func(net.IP) (net.Listener, error) {
	return func(ip net.IP) (net.Listener, error) {
		r.mu.Lock()
		r.addrs = append(r.addrs, ip.String())
		r.mu.Unlock()
		if inner != nil {
			return inner(ip)
		}
		return nil, io.EOF
	}
}

func (r *recordingListen) Addrs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.addrs))
	copy(out, r.addrs)
	return out
}

type recordingUDP struct {
	mu     sync.Mutex
	addrs  []string
	writes []string
}

func (r *recordingUDP) wrap(inner func(net.IP) (net.PacketConn, error)) func(net.IP) (net.PacketConn, error) {
	return func(ip net.IP) (net.PacketConn, error) {
		r.mu.Lock()
		r.addrs = append(r.addrs, ip.String())
		r.mu.Unlock()
		if inner == nil {
			return nil, io.EOF
		}
		pc, err := inner(ip)
		if err != nil {
			return nil, err
		}
		return &recordingPacketConn{PacketConn: pc, rec: r}, nil
	}
}

func (r *recordingUDP) Addrs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.addrs))
	copy(out, r.addrs)
	return out
}

func (r *recordingUDP) Writes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.writes))
	copy(out, r.writes)
	return out
}

type recordingPacketConn struct {
	net.PacketConn
	rec *recordingUDP
}

func (c *recordingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.rec != nil && addr != nil {
		c.rec.mu.Lock()
		c.rec.writes = append(c.rec.writes, addr.String())
		c.rec.mu.Unlock()
	}
	return c.PacketConn.WriteTo(p, addr)
}

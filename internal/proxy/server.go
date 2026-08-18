package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm"
)

// DefaultShutdownWait is the serve drain deadline when none is configured.
const DefaultShutdownWait = 5 * time.Second

// Options construct a Server.
type Options struct {
	Address string
	Spec    model.Spec
	Sink    Sink
	// Resolver overrides net.DefaultResolver (tests: name→IMDS).
	Resolver Resolver
	// DialContext, when set, replaces dialTCP (tests record outbound).
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Authority is the lab CA. When nil and spec.tls.intercept is true,
	// New generates or loads one from spec.tls.ca.
	Authority *tlsmitm.Authority
}

// Server is the HTTP/1.1 forward-proxy listener.
type Server struct {
	addr     string
	spec     atomic.Pointer[model.Spec]
	sink     Sink
	resolver Resolver
	dialFn   func(ctx context.Context, network, addr string) (net.Conn, error)
	auth     *tlsmitm.Authority
	gate     *gate
	metrics  *Metrics
	tr       *http.Transport

	ctx    context.Context
	cancel context.CancelFunc

	rawLn net.Listener
	http  *http.Server

	mu        sync.Mutex
	hijacked  map[net.Conn]struct{}
	hijackWG  sync.WaitGroup
	started   bool
	stopped   bool
	accepting atomic.Bool
}

// New validates opts. Start binds and serves.
func New(opts Options) (*Server, error) {
	if opts.Address == "" {
		return nil, errors.New("proxy: Address is required")
	}
	spec := withSpecDefaults(opts.Spec)
	sink := opts.Sink
	if sink == nil {
		sink = NewNull()
	}
	res := opts.Resolver
	if res == nil {
		res = defaultResolver{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		addr:     opts.Address,
		sink:     sink,
		resolver: res,
		dialFn:   opts.DialContext,
		gate:     newGate(),
		metrics:  newMetrics(),
		ctx:      ctx,
		cancel:   cancel,
		hijacked: make(map[net.Conn]struct{}),
	}
	s.spec.Store(&spec)
	s.tr = s.newCleartextTransport()
	auth := opts.Authority
	if auth == nil && spec.TLS.Intercept {
		var err error
		auth, err = tlsmitm.New(tlsmitm.Options{
			Mode:               spec.TLS.CA.Mode,
			CertFile:           spec.TLS.CA.CertFile,
			KeyFile:            spec.TLS.CA.KeyFile,
			InsecureSkipVerify: spec.TLS.Upstream.InsecureSkipVerify,
			ExtraCAFiles:       spec.TLS.Upstream.ExtraCAFiles,
		})
		if err != nil {
			cancel()
			return nil, fmt.Errorf("proxy: lab CA: %w", err)
		}
	}
	s.auth = auth
	return s, nil
}

// Authority is the in-process lab CA (nil when intercept is off).
func (s *Server) Authority() *tlsmitm.Authority {
	if s == nil {
		return nil
	}
	return s.auth
}

const (
	defaultMaxSessions      = 256
	defaultMaxSessionsPerIP = 32
	defaultMaxInFlight      = 64
	defaultMaxInFlightB     = int64(64 << 20)
	defaultSessionTimeout   = 10 * time.Minute
	defaultIdleTimeout      = 120 * time.Second
	defaultHeaderTimeout    = 10 * time.Second
	defaultDialTimeout      = 10 * time.Second
	defaultUpstreamTimeout  = 60 * time.Second
	defaultMaxBodyBytes     = int64(1 << 20)
	defaultProxyHostname    = "labmitm.lab"
)

func withSpecDefaults(spec model.Spec) model.Spec {
	a := &spec.Proxy.Admission
	if a.MaxSessions == 0 {
		a.MaxSessions = defaultMaxSessions
	}
	if a.MaxSessionsPerIP == 0 {
		a.MaxSessionsPerIP = defaultMaxSessionsPerIP
	}
	if a.MaxInFlight == 0 {
		a.MaxInFlight = defaultMaxInFlight
	}
	if a.MaxInFlightBytes == 0 {
		a.MaxInFlightBytes = defaultMaxInFlightB
	}
	if a.SessionTimeout == 0 {
		a.SessionTimeout = defaultSessionTimeout
	}
	if a.IdleTimeout == 0 {
		a.IdleTimeout = defaultIdleTimeout
	}
	if a.HeaderTimeout == 0 {
		a.HeaderTimeout = defaultHeaderTimeout
	}
	if a.DialTimeout == 0 {
		a.DialTimeout = defaultDialTimeout
	}
	if a.UpstreamTimeout == 0 {
		a.UpstreamTimeout = defaultUpstreamTimeout
	}
	if spec.Store.MaxBodyBytes == 0 {
		spec.Store.MaxBodyBytes = defaultMaxBodyBytes
	}
	if spec.Proxy.Hostname == "" {
		spec.Proxy.Hostname = defaultProxyHostname
	}
	if len(spec.TLS.Ports) == 0 {
		spec.TLS.Ports = []int{443}
	}
	// Zero Targets (caller skipped the loader) must still deny IMDS/link-local.
	// A loaded spec has at least one bool true (allowLoopback default), so
	// explicit denyCloudMetadata:false is preserved.
	if zeroTargets(spec.Proxy.Targets) {
		spec.Proxy.Targets.DenyCloudMetadata = true
		spec.Proxy.Targets.DenyLinkLocal = true
		spec.Proxy.Targets.AllowLoopback = true
	}
	return spec
}

func zeroTargets(t model.TargetsSpec) bool {
	return !t.DenyCloudMetadata && !t.DenyLinkLocal && !t.AllowLoopback &&
		len(t.AllowHosts) == 0 && len(t.DenyHosts) == 0
}

func (s *Server) specNow() model.Spec {
	p := s.spec.Load()
	if p == nil {
		return withSpecDefaults(model.Spec{})
	}
	return *p
}

func (s *Server) newCleartextTransport() *http.Transport {
	proto := http1Only()
	ad := s.specNow().Proxy.Admission
	return &http.Transport{
		Proxy:                 nil, // never honor HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
		DialContext:           s.dialPinned,
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       ad.IdleTimeout,
		ResponseHeaderTimeout: ad.UpstreamTimeout,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		Protocols:             proto,
	}
}

func http1Only() *http.Protocols {
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetHTTP2(false)
	p.SetUnencryptedHTTP2(false)
	return &p
}

func (s *Server) dialPinned(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.dialFn != nil {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(host) == nil {
			return nil, fmt.Errorf("proxy: refusing hostname dial %q (must be pinned IP)", addr)
		}
		return s.dialFn(ctx, network, addr)
	}
	return dialTCP(ctx, network, addr, s.specNow().Proxy.Admission.DialTimeout)
}

// Start binds the listener and serves in the background.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("proxy: already started")
	}
	if s.stopped {
		return errors.New("proxy: start after shutdown")
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("proxy: listen: %w", err)
	}
	s.rawLn = ln
	ad := s.specNow().Proxy.Admission
	peeked := &peekListener{
		Listener: ln,
		reject: func() {
			s.metrics.reject("socks")
		},
	}
	proto := http1Only()
	s.http = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: ad.HeaderTimeout,
		IdleTimeout:       ad.IdleTimeout,
		MaxHeaderBytes:    1 << 20,
		Protocols:         proto,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context {
			return s.ctx
		},
	}
	s.started = true
	s.accepting.Store(true)
	go func() { _ = s.http.Serve(peeked) }()
	return nil
}

// Addr is the bound proxy address.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rawLn == nil {
		return nil
	}
	return s.rawLn.Addr()
}

// Accepting reports whether the listener is still taking new conns.
func (s *Server) Accepting() bool {
	return s.accepting.Load()
}

// Metrics returns the in-process counters.
func (s *Server) Metrics() *Metrics {
	return s.metrics
}

// Shutdown stops accept, drains hijacked tunnels, then the http.Server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.accepting.Store(false)
	s.cancel()
	s.mu.Lock()
	s.stopped = true
	hs := s.http
	s.mu.Unlock()
	var first error
	if hs != nil {
		if err := hs.Shutdown(ctx); err != nil {
			first = err
		}
	}
	done := make(chan struct{})
	go func() {
		s.hijackWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		s.closeHijacked()
		<-done
		if first == nil {
			first = ctx.Err()
		}
	}
	s.mu.Lock()
	if s.tr != nil {
		s.tr.CloseIdleConnections()
	}
	s.mu.Unlock()
	return first
}

func (s *Server) beginHijacked() {
	s.hijackWG.Add(1)
}

func (s *Server) endHijacked() {
	s.hijackWG.Done()
}

func (s *Server) track(c net.Conn) {
	if c == nil {
		return
	}
	s.mu.Lock()
	s.hijacked[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	if c == nil {
		return
	}
	s.mu.Lock()
	delete(s.hijacked, c)
	s.mu.Unlock()
}

func (s *Server) closeHijacked() {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.hijacked))
	for c := range s.hijacked {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (s *Server) capture(f *model.Flow) {
	if s.sink == nil || f == nil {
		return
	}
	s.sink.Insert(s.ctx, f)
}

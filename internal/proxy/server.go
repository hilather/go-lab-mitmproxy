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
	"github.com/hilather/go-lab-mitmproxy/internal/observability"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
	"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm"
)

// DefaultShutdownWait is the serve drain deadline when none is configured.
const DefaultShutdownWait = 5 * time.Second

// Options construct a Server.
type Options struct {
	Address string
	Spec    model.Spec
	Sink    Sink
	// Store is the breakpoint inbox (WaitPaused). When nil, AdaptStore's
	// wrapped store is used if Sink is AdaptStore; otherwise breakpoint
	// times out and the session continues unmodified.
	Store store.Store
	// Resolver overrides net.DefaultResolver (tests: name→IMDS).
	Resolver Resolver
	// DialContext, when set, replaces dialTCP (tests record outbound).
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// OrigDestAddress overrides spec.listeners.originalDestination.address.
	OrigDestAddress string
	// OriginalDst, when set, replaces SO_ORIGINAL_DST (tests: mocked dest).
	OriginalDst func(net.Conn) (net.IP, int, error)
	// Authority is the lab CA. When nil and spec.tls.intercept is true
	// and Snapshots is nil, New generates or loads one from spec.tls.ca
	// (test fallback). Production compiles the CA in internal/compiler.
	Authority *tlsmitm.Authority
	// Snapshots is the atomic config pointer. ServeHTTP / CONNECT load
	// once and pin the snapshot for the rest of the session.
	Snapshots *snapshot.Store
	// Metrics and Logger are optional. Nil is a no-op.
	Metrics *observability.Registry
	Logger  *observability.Logger
}

// Server is the HTTP/1.1 forward-proxy listener.
type Server struct {
	addr     string
	spec     atomic.Pointer[model.Spec]
	sink     Sink
	inbox    store.Store
	resolver Resolver
	dialFn   func(ctx context.Context, network, addr string) (net.Conn, error)
	auth     *tlsmitm.Authority
	snaps    *snapshot.Store
	gate     *gate
	metrics  *Metrics
	tr       *http.Transport

	ctx    context.Context
	cancel context.CancelFunc

	rawLn        net.Listener
	origLn       net.Listener
	httpLn       *chanListener
	http         *http.Server
	origDestBind string
	origDestFn   func(net.Conn) (net.IP, int, error)

	mu          sync.Mutex
	hijacked    map[net.Conn]struct{}
	dispatching map[net.Conn]struct{}
	hijackWG    sync.WaitGroup
	acceptWG    sync.WaitGroup
	dispatchWG  sync.WaitGroup
	started     bool
	stopped     bool
	accepting   atomic.Bool
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
		addr:         opts.Address,
		sink:         sink,
		inbox:        opts.Store,
		resolver:     res,
		dialFn:       opts.DialContext,
		origDestBind: opts.OrigDestAddress,
		origDestFn:   opts.OriginalDst,
		snaps:        opts.Snapshots,
		gate:         newGate(),
		metrics:      newMetrics(),
		ctx:          ctx,
		cancel:       cancel,
		hijacked:     make(map[net.Conn]struct{}),
		dispatching:  make(map[net.Conn]struct{}),
	}
	s.metrics.attach(opts.Metrics, opts.Logger)
	if s.inbox == nil {
		if ss, ok := sink.(*storeSink); ok {
			s.inbox = ss.s
		}
	}
	s.spec.Store(&spec)
	s.tr = s.newCleartextTransport()
	auth := opts.Authority
	// Compiler owns CA minting. Tests without a snapshot store still
	// generate when intercept is on so existing TLS fixtures keep working.
	if auth == nil && spec.TLS.Intercept && opts.Snapshots == nil {
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
	// Process-wide cleartext Transport: Start-time spec (not live apply).
	return s.dialPinnedTO(ctx, network, addr, s.specNow().Proxy.Admission.DialTimeout)
}

func (s *Server) dialPinnedTO(ctx context.Context, network, addr string, dialTO time.Duration) (net.Conn, error) {
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
	if dialTO <= 0 {
		dialTO = defaultDialTimeout
	}
	return dialTCP(ctx, network, addr, dialTO)
}

// Start binds the listener and serves in the background.
func (s *Server) Start() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("proxy: already started")
	}
	if s.stopped {
		s.mu.Unlock()
		return errors.New("proxy: start after shutdown")
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("proxy: listen: %w", err)
	}
	s.rawLn = ln
	spec := s.specNow()
	if spec.Listeners.OriginalDestination.Enabled {
		if !origDestSupported {
			_ = ln.Close()
			s.rawLn = nil
			s.mu.Unlock()
			return fmt.Errorf("proxy: originalDestination requires linux (REDIRECT + SO_ORIGINAL_DST)")
		}
		odAddr := s.origDestBind
		if odAddr == "" {
			odAddr = spec.Listeners.OriginalDestination.Address
		}
		if odAddr == "" {
			odAddr = "127.0.0.1:8890"
		}
		origLn, err := net.Listen("tcp", odAddr)
		if err != nil {
			_ = ln.Close()
			s.rawLn = nil
			s.mu.Unlock()
			return fmt.Errorf("proxy: originalDestination listen: %w", err)
		}
		s.origLn = origLn
	}
	httpLn := newChanListener(ln.Addr())
	s.httpLn = httpLn
	ad := spec.Proxy.Admission
	proto := http1Only()
	s.http = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: ad.HeaderTimeout,
		IdleTimeout:       ad.IdleTimeout,
		MaxHeaderBytes:    1 << 20,
		Protocols:         proto,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:          log.New(io.Discard, "", 0),
		ConnContext:       s.connContext,
		BaseContext: func(net.Listener) context.Context {
			return s.ctx
		},
	}
	s.started = true
	s.accepting.Store(true)
	orig := s.origLn
	hs := s.http
	s.mu.Unlock()
	s.acceptWG.Add(1)
	go s.acceptLoop(ln, kindProxy)
	if orig != nil {
		s.acceptWG.Add(1)
		go s.acceptLoop(orig, kindOrigDest)
	}
	go func() { _ = hs.Serve(httpLn) }()
	return nil
}

func (s *Server) acceptLoop(rawLn net.Listener, kind connKind) {
	defer s.acceptWG.Done()
	if rawLn == nil {
		s.accepting.Store(false)
		return
	}
	var tempDelay time.Duration
	for {
		c, err := rawLn.Accept()
		if err != nil {
			if !s.accepting.Load() || shutdownClosed(err) {
				s.accepting.Store(false)
				return
			}
			if acceptTemporary(err) {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
				if !s.sleepAcceptBackoff(tempDelay) {
					s.accepting.Store(false)
					return
				}
				continue
			}
			s.accepting.Store(false)
			return
		}
		tempDelay = 0
		if !s.accepting.Load() {
			_ = c.Close()
			s.accepting.Store(false)
			return
		}
		s.dispatchWG.Add(1)
		s.trackDispatch(c)
		go s.dispatchConn(c, kind)
	}
}

func acceptTemporary(err error) bool {
	if err == nil {
		return false
	}
	t, ok := err.(interface{ Temporary() bool })
	return ok && t.Temporary()
}

func (s *Server) sleepAcceptBackoff(d time.Duration) bool {
	if d <= 0 {
		return s.ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-s.ctx.Done():
		return false
	}
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

// OrigDestAddr is the bound original-destination address, or nil.
func (s *Server) OrigDestAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origLn == nil {
		return nil
	}
	return s.origLn.Addr()
}

// Accepting reports whether the listener is still taking new conns.
func (s *Server) Accepting() bool {
	return s.accepting.Load()
}

// OrigDestAccepting reports whether the orig-dest listener is accepting.
func (s *Server) OrigDestAccepting() bool {
	s.mu.Lock()
	orig := s.origLn
	s.mu.Unlock()
	return orig != nil && s.accepting.Load()
}

// Metrics returns the in-process counters.
func (s *Server) Metrics() *Metrics {
	return s.metrics
}

// Shutdown: accepting=false → close rawLn → wait acceptLoop →
// close in-peek dispatch conns → wait dispatch goroutines →
// chanListener.Close → http.Server.Shutdown → hijack drain (D42).
func (s *Server) Shutdown(ctx context.Context) error {
	s.accepting.Store(false)
	s.cancel()
	s.mu.Lock()
	s.stopped = true
	raw := s.rawLn
	orig := s.origLn
	httpLn := s.httpLn
	hs := s.http
	s.mu.Unlock()
	var first error
	if err := closeQuiet(raw); err != nil && first == nil {
		first = err
	}
	if err := closeQuiet(orig); err != nil && first == nil {
		first = err
	}
	s.acceptWG.Wait()
	s.closeDispatching()
	if err := waitWG(ctx, &s.dispatchWG, s.closeDispatching); err != nil && first == nil {
		first = err
	}
	if err := closeQuiet(httpLn); err != nil && first == nil {
		first = err
	}
	if hs != nil {
		if err := hs.Shutdown(ctx); err != nil && !shutdownClosed(err) && first == nil {
			first = err
		}
	}
	if err := waitWG(ctx, &s.hijackWG, s.closeHijacked); err != nil && first == nil {
		first = err
	}
	s.mu.Lock()
	if s.tr != nil {
		s.tr.CloseIdleConnections()
	}
	s.mu.Unlock()
	return first
}

func waitWG(ctx context.Context, wg *sync.WaitGroup, abort func()) error {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		if abort != nil {
			abort()
		}
		<-done
		return ctx.Err()
	}
}

func closeQuiet(c io.Closer) error {
	if c == nil {
		return nil
	}
	err := c.Close()
	if shutdownClosed(err) {
		return nil
	}
	return err
}

func shutdownClosed(err error) bool {
	return err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed)
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

func (s *Server) trackDispatch(c net.Conn) {
	if c == nil {
		return
	}
	s.mu.Lock()
	s.dispatching[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrackDispatch(c net.Conn) {
	if c == nil {
		return
	}
	s.mu.Lock()
	delete(s.dispatching, c)
	s.mu.Unlock()
}

func (s *Server) closeDispatching() {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.dispatching))
	for c := range s.dispatching {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func stampSession(f *model.Flow, sess *ruleSession) {
	if f == nil || sess == nil {
		return
	}
	if f.Via == "" && sess.via != "" {
		f.Via = sess.via
	}
	if f.SOCKS == nil && sess.socks != nil {
		f.SOCKS = sess.socks
	}
}

func (s *Server) capture(f *model.Flow, sess *ruleSession) {
	stampSession(f, sess)
	if s.sink == nil || f == nil {
		return
	}
	if sess != nil {
		if sess.via != "" && f.Via == "" {
			f.Via = sess.via
		}
		if sess.originalDest != "" && f.OriginalDest == "" {
			f.OriginalDest = sess.originalDest
		}
	}
	s.metrics.flow(f)
	if ss, ok := s.sink.(*storeSink); ok {
		_, err := ss.s.Insert(s.ctx, s.sessionEpoch(sess), f)
		if err != nil && errors.Is(err, store.ErrFull) {
			s.metrics.storeFullInc()
			if ss.onFull != nil {
				ss.onFull()
			}
		}
		// ErrStaleEpoch: hop started before reset; capture is discarded.
		return
	}
	s.sink.Insert(s.ctx, f)
}

// AdaptStore wraps a store.Store as a best-effort Sink. Insert errors
// (including ErrFull) are ignored so the client hop still succeeds.
func AdaptStore(s store.Store) Sink {
	return AdaptStoreNotify(s, nil)
}

// AdaptStoreNotify is AdaptStore with an optional full-reject hook (tests/metrics).
func AdaptStoreNotify(s store.Store, onFull func()) Sink {
	if s == nil {
		return NewNull()
	}
	return &storeSink{s: s, onFull: onFull}
}

type storeSink struct {
	s      store.Store
	onFull func()
}

func (a *storeSink) Insert(ctx context.Context, f *model.Flow) {
	if a == nil || a.s == nil || f == nil {
		return
	}
	_, err := a.s.Insert(ctx, a.s.Epoch(), f)
	if err != nil && errors.Is(err, store.ErrFull) && a.onFull != nil {
		a.onFull()
	}
}

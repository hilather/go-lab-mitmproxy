package rest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/auth"
	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/observability"
)

const (
	// DefaultAddr is the first-GA management listen address.
	DefaultAddr = config.DefaultMgmtAddress

	// DefaultMaxBodyBytes matches the config document bound (1 MiB).
	DefaultMaxBodyBytes = 1 << 20

	// DefaultRequestTimeout is the per-request handler deadline.
	DefaultRequestTimeout = 30 * time.Second

	// DefaultReadHeaderTimeout bounds slowloris-style header stalls.
	DefaultReadHeaderTimeout = 5 * time.Second

	// DefaultReadTimeout bounds the whole request read.
	DefaultReadTimeout = 30 * time.Second

	// DefaultMaxConcurrent is the in-process overlapping-request cap.
	DefaultMaxConcurrent = 256

	headerRequestID   = "X-Request-ID"
	headerIdempotency = "Idempotency-Key"
	headerIfMatch     = "If-Match"
	headerExpected    = "X-LabMITM-Expected-Revision"
	headerRevision    = "X-LabMITM-Revision"
	headerAllow       = "Allow"

	requestURNPrefix = "urn:labmitm:request:"
)

// Config constructs a management HTTP server.
type Config struct {
	// Addr is the listen address. Empty becomes DefaultAddr (127.0.0.1:8088).
	Addr string
	// Service is required. Handlers call it and do not mutate snapshots.
	Service app.Service
	// AllowedOrigins are extra Origins accepted besides loopback. Empty denies
	// every non-loopback Origin (CORS/DNS-rebinding default-deny).
	AllowedOrigins []string
	// Live overrides liveness. Nil is always live while the process serves.
	Live func() bool
	// Ready overrides readiness. Nil is app.Status.Ready.
	Ready func() bool
	// MaxBodyBytes caps decoded request bodies. Non-positive uses DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// RequestTimeout is the handler context deadline. Non-positive uses DefaultRequestTimeout.
	RequestTimeout time.Duration
	// ReadHeaderTimeout, ReadTimeout, WriteTimeout apply when ListenAndServe runs.
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	// MaxConcurrent admits at most this many overlapping requests. Non-positive uses DefaultMaxConcurrent.
	MaxConcurrent int
	// RatePerSec is a coarse per-source QPS. Zero uses config default. Negative disables.
	RatePerSec float64
	// RateBurst is the per-source burst. Zero uses config default.
	RateBurst float64
	// PublicMetrics serves GET /v1/metrics. False returns not_found.
	PublicMetrics bool
	// Metrics is the process registry. Nil skips HTTP counters and /v1/metrics body.
	Metrics *observability.Registry
	// Logger emits slog JSON events. Nil is a no-op.
	Logger *observability.Logger
	// SSEHeartbeat is the events stream comment interval. Non-positive uses 15s.
	SSEHeartbeat time.Duration
	// Auth is the shared verifier. Nil is deny-all (not allow-all).
	Auth *auth.Verifier
	// Sessions is the REST-only UI session table. Nil becomes an empty store.
	Sessions *auth.Store
	// CookieSecure forces the Secure flag (management TLS).
	CookieSecure bool
	// UI serves the embedded stub/SPA when a request is not a native /v1 or MCP path.
	// rest must not import internal/web; cmd wires this.
	UI http.Handler
	// UIEnabled reports spec.ui.enabled. Nil means enabled whenever UI != nil.
	UIEnabled func() bool
	// Mounts are additional handlers (MCP POST /mcp) served after the shared
	// timeout, inflight, and origin gates but ahead of native /v1 routing.
	// rest must not import internal/control/mcp; cmd wires this.
	Mounts map[string]http.Handler
}

// Server is the stdlib net/http management listener.
type Server struct {
	cfg          Config
	svc          app.Service
	routes       []compiledRoute
	handler      http.Handler
	maxBody      int64
	timeout      time.Duration
	inflight     chan struct{}
	rate         *limiter
	metrics      *observability.Registry
	logger       *observability.Logger
	sseHeartbeat time.Duration

	cursorMu  sync.Mutex
	cursorKey []byte

	mounts *http.ServeMux

	mu     sync.Mutex
	http   *http.Server
	ln     net.Listener
	closed atomic.Bool
}

// New builds a Server. Routes come from the frozen capability registry.
func New(cfg Config) (*Server, error) {
	if cfg.Service == nil {
		return nil, errors.New("rest: Service is required")
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	n := cfg.MaxConcurrent
	if n <= 0 {
		n = DefaultMaxConcurrent
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	hb := cfg.SSEHeartbeat
	if hb <= 0 {
		hb = sseHeartbeat
	}
	if cfg.Sessions == nil {
		cfg.Sessions = auth.NewStore(auth.DefaultSessionConfig())
	}
	s := &Server{
		cfg:          cfg,
		svc:          cfg.Service,
		routes:       compileRoutes(capabilities.All()),
		maxBody:      maxBody,
		timeout:      timeout,
		inflight:     make(chan struct{}, n),
		rate:         newLimiter(cfg.RatePerSec, cfg.RateBurst),
		metrics:      cfg.Metrics,
		logger:       cfg.Logger,
		sseHeartbeat: hb,
		cursorKey:    key,
	}
	s.svc.OnReset(s.RotateCursors)
	s.svc.OnReset(s.reloadAuth)
	s.svc.OnApply(s.reloadAuth)
	if len(cfg.Mounts) > 0 {
		mux := http.NewServeMux()
		for path, h := range cfg.Mounts {
			mux.Handle(path, h)
		}
		s.mounts = mux
	}
	s.handler = http.HandlerFunc(s.serveHTTP)
	return s, nil
}

// Handler returns the management mux. Safe for httptest.NewServer / ServeHTTP.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// ListenAndServe binds Addr (default 127.0.0.1:8088) and serves until Shutdown.
func (s *Server) ListenAndServe() error {
	addr := s.cfg.Addr
	if addr == "" {
		addr = DefaultAddr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Attach records ln so Addr() is correct before Serve returns.
func (s *Server) Attach(ln net.Listener) {
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
}

// Serve serves on ln until Shutdown. ln is closed by Shutdown or on return.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		_ = ln.Close()
		return nil
	}
	if s.http != nil {
		s.mu.Unlock()
		_ = ln.Close()
		return errors.New("rest: server already started")
	}
	rh := s.cfg.ReadHeaderTimeout
	if rh <= 0 {
		rh = DefaultReadHeaderTimeout
	}
	rt := s.cfg.ReadTimeout
	if rt <= 0 {
		rt = DefaultReadTimeout
	}
	hs := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: rh,
		ReadTimeout:       rt,
		WriteTimeout:      s.cfg.WriteTimeout,
		MaxHeaderBytes:    1 << 16,
	}
	s.http = hs
	s.ln = ln
	alreadyClosed := s.closed.Load()
	s.mu.Unlock()
	if alreadyClosed {
		_ = ln.Close()
		return nil
	}
	err := hs.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown closes the listener and waits for in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error {
	s.closed.Store(true)
	s.mu.Lock()
	hs := s.http
	ln := s.ln
	s.mu.Unlock()
	if hs != nil {
		return hs.Shutdown(ctx)
	}
	if ln != nil {
		return ln.Close()
	}
	return nil
}

// Addr returns the bound address after Serve, or the configured listen address.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		return s.ln.Addr().String()
	}
	if s.cfg.Addr != "" {
		return s.cfg.Addr
	}
	return DefaultAddr
}

// RotateCursors issues a new HMAC key. Reset/restart invalidate list cursors.
func (s *Server) RotateCursors() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return
	}
	s.cursorMu.Lock()
	s.cursorKey = key
	s.cursorMu.Unlock()
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
	w = sw
	reqID := requestID(r)
	w.Header().Set(headerRequestID, reqID)
	r.Header.Set(headerRequestID, reqID)
	instance := requestURNPrefix + reqID
	capID := ""
	defer func() {
		s.observeHTTP(capID, sw.status(), start, reqID)
	}()

	if err := checkOrigin(r.Header.Get("Origin"), s.cfg.AllowedOrigins); err != nil {
		s.writeProblem(w, r, instance, err)
		return
	}
	if r.Method == http.MethodOptions {
		s.writeProblem(w, r, instance, domainerr.Forbidden("CORS is disabled"))
		return
	}

	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		s.writeProblem(w, r, instance, domainerr.RateLimited("too many concurrent management requests"))
		return
	}

	ctx := r.Context()
	var cancel context.CancelFunc
	if s.timeout > 0 && !isWaitPath(r.URL.Path) && !isSSEPath(r.URL.Path) && !s.isMountedPath(r) {
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	r = r.WithContext(ctx)

	defer func() {
		if rec := recover(); rec != nil {
			s.writeProblem(w, r, instance, domainerr.Internal("internal error"))
		}
	}()

	// MCP (and other cmd-wired mounts) run after origin/inflight/timeout so
	// POST /mcp cannot bypass the shared gates. MCP applies its own auth.
	if s.dispatchMount(w, r, instance) {
		return
	}

	rt, params, pathOK, methodOK := matchRoute(s.routes, r.Method, r.URL.Path)
	if pathOK {
		capID = string(rt.cap.ID)
	}
	if !pathOK {
		if s.tryUI(w, r, instance) {
			return
		}
		s.writeProblem(w, r, instance, domainerr.NotFound("not found"))
		return
	}
	if !methodOK {
		w.Header().Set(headerAllow, allowedMethods(s.routes, r.URL.Path))
		s.writeProblem(w, r, instance, domainerr.MethodNotAllowed("method not allowed"))
		return
	}

	if !isHealthCap(rt.cap) {
		if err := s.rate.allow(r.RemoteAddr); err != nil {
			s.writeProblem(w, r, instance, err)
			return
		}
	}

	actor, err := s.authenticate(r, isHealthCap(rt.cap))
	if err != nil {
		s.writeProblem(w, r, instance, err)
		return
	}
	if err := s.authorize(r, actor, rt.cap); err != nil {
		s.writeProblem(w, r, instance, err)
		return
	}
	s.dispatch(w, r, instance, actor, rt, params)
}

func (s *Server) reloadAuth() {
	if s.cfg.Auth == nil {
		return
	}
	appSvc, ok := s.svc.(*app.App)
	if !ok {
		return
	}
	snap := appSvc.Active()
	if snap == nil || snap.Canonical == nil {
		return
	}
	next, err := auth.FromSpec(snap.Canonical.Spec.Management.Auth)
	if err != nil {
		// Keep the previous verifier and live UI sessions.
		return
	}
	// Do not swap in an allow-all / empty-bearer index; keep the live verifier.
	if err := next.RequireListen(); err != nil {
		return
	}
	changed := !s.cfg.Auth.Equivalent(next)
	s.cfg.Auth.Replace(next)
	if changed && s.cfg.Sessions != nil {
		s.cfg.Sessions.Clear()
	}
}

func isHealthCap(cap capabilities.Capability) bool {
	return cap.ID == capabilities.HealthLive || cap.ID == capabilities.HealthReady
}

func isWaitPath(path string) bool {
	return strings.HasSuffix(path, ":wait")
}

func isSSEPath(path string) bool {
	return strings.HasSuffix(path, "/events/stream")
}

func (s *Server) isMountedPath(r *http.Request) bool {
	if s == nil || s.mounts == nil || r == nil {
		return false
	}
	_, pattern := s.mounts.Handler(r)
	return pattern != ""
}

func (s *Server) dispatchMount(w http.ResponseWriter, r *http.Request, instance string) bool {
	if s.mounts == nil {
		return false
	}
	h, pattern := s.mounts.Handler(r)
	if pattern == "" {
		return false
	}
	if err := s.rate.allow(r.RemoteAddr); err != nil {
		s.writeProblem(w, r, instance, err)
		return true
	}
	h.ServeHTTP(w, r)
	return true
}

func requestID(r *http.Request) string {
	if id := r.Header.Get(headerRequestID); id != "" {
		return id
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-fallback"
	}
	return hex.EncodeToString(b[:])
}

func (s *Server) isLive() bool {
	if s.cfg.Live != nil {
		return s.cfg.Live()
	}
	return !s.closed.Load()
}

func (s *Server) isReady(ctx context.Context) bool {
	if s.cfg.Ready != nil {
		return s.cfg.Ready()
	}
	st, err := s.svc.Status(ctx, app.Actor{ID: "ready", Class: "startup", Transport: "rest"})
	return err == nil && st != nil && st.Ready
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) status() int {
	if w == nil || w.code == 0 {
		return http.StatusOK
	}
	return w.code
}

func (s *Server) observeHTTP(capability string, status int, start time.Time, reqID string) {
	if s == nil {
		return
	}
	if capability == "" {
		capability = "unknown"
	}
	cls := observability.CodeClass(status)
	if s.metrics != nil {
		s.metrics.Inc(observability.MetricHTTPRequestsTotal, map[string]string{
			"capability": capability,
			"code_class": cls,
		}, 1)
		s.metrics.Observe(observability.MetricHTTPRequestDuration, map[string]string{
			"capability": capability,
		}, time.Since(start).Seconds())
	}
	if s.logger != nil {
		s.logger.Log(observability.Record{
			Event:      observability.EventHTTPRequest,
			Component:  "rest",
			RequestID:  reqID,
			Capability: capability,
			Result:     cls,
			DurationMS: float64(time.Since(start).Milliseconds()),
		})
	}
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

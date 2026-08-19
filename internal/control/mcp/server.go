package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/auth"
	"github.com/hilather/go-lab-mitmproxy/internal/buildinfo"
	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// ProtocolVersion is the only MCP revision first GA speaks (ADR 0006).
	ProtocolVersion = "2026-07-28"

	// SDKModule is the official Go SDK module path.
	SDKModule = "github.com/modelcontextprotocol/go-sdk"

	// SDKVersion is the pinned official SDK tag.
	SDKVersion = "v1.7.0"

	// DefaultPath is the Streamable HTTP mount on the management listener.
	DefaultPath = config.DefaultMCPPath

	// DefaultMaxBodyBytes matches the REST management bound (1 MiB).
	DefaultMaxBodyBytes = 1 << 20

	// DefaultRequestTimeout is the per-request handler deadline.
	DefaultRequestTimeout = 30 * time.Second

	// DefaultMaxConcurrent is the in-process overlapping-request cap.
	DefaultMaxConcurrent = 256

	headerProtocolVersion = "Mcp-Protocol-Version"
	headerMethod          = "Mcp-Method"
	headerName            = "Mcp-Name"
	headerRequestID       = "X-Request-ID"
	headerOrigin          = "Origin"
	headerAuthorization   = "Authorization"

	methodListen = "subscriptions/listen"
	toolWait     = "mitm_flows_wait"
)

// Config constructs the MCP adapter.
type Config struct {
	// Service is required. Handlers call it and do not mutate snapshots.
	Service app.Service
	// AllowedOrigins are extra Origins accepted besides loopback. Empty denies
	// every non-loopback Origin (DNS-rebinding default-deny).
	AllowedOrigins []string
	// AllowLegacyClients relaxes the HTTP-level protocol pin so MCPJungle can
	// negotiate during initialize (D15). subscriptions/listen stays 2026-07-28.
	AllowLegacyClients bool
	// RatePerSec is the per-source management QPS. Zero uses the shared default.
	// Negative disables the token bucket (concurrency cap still applies).
	RatePerSec float64
	// RateBurst is the per-source burst. Zero uses the shared default.
	RateBurst float64
	// MaxBodyBytes caps decoded request bodies. Non-positive uses DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// RequestTimeout is the handler context deadline. Non-positive uses DefaultRequestTimeout.
	RequestTimeout time.Duration
	// MaxConcurrent admits at most this many overlapping requests. Non-positive uses DefaultMaxConcurrent.
	MaxConcurrent int
	// Auth is the shared verifier. Nil keeps unit tests stub-open (Basic still rejected).
	Auth *auth.Verifier
	// FixedActor is used by mcp-stdio when there is no HTTP Authorization header.
	FixedActor *app.Actor
}

// Server is the official-SDK adapter. Third-party MCP types do not escape it.
type Server struct {
	cfg      Config
	svc      app.Service
	sdk      *sdk.Server
	http     *sdk.StreamableHTTPHandler
	maxBody  int64
	timeout  time.Duration
	inflight chan struct{}
	rate     *limiter
	closed   atomic.Bool

	cursorMu  sync.Mutex
	cursorKey []byte

	inboxCancel func()
}

type ctxKey int

const (
	ctxActor ctxKey = iota
	ctxRequestID
)

// New builds a Server. Tools and resources come from the frozen registry.
func New(cfg Config) (*Server, error) {
	if cfg.Service == nil {
		return nil, errors.New("mcp: Service is required")
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

	info := buildinfo.Current()
	impl := &sdk.Implementation{
		Name:    "labmitm",
		Title:   "LabMITM",
		Version: info.Version,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	s := &Server{
		cfg:       cfg,
		svc:       cfg.Service,
		maxBody:   maxBody,
		timeout:   timeout,
		inflight:  make(chan struct{}, n),
		rate:      newLimiter(cfg.RatePerSec, cfg.RateBurst),
		cursorKey: key,
	}
	sdkOpts := &sdk.ServerOptions{
		Instructions: "LabMITM control plane. Use typed mitm_* tools; do not assume connection state. Protocol " + ProtocolVersion + ".",
		Logger:       logger,
		Capabilities: &sdk.ServerCapabilities{
			Logging:   nil,
			Tools:     &sdk.ToolCapabilities{ListChanged: false},
			Resources: &sdk.ResourceCapabilities{ListChanged: false, Subscribe: true},
		},
		SchemaCache:        sdk.NewSchemaCache(),
		SubscribeHandler:   s.onSubscribe,
		UnsubscribeHandler: s.onUnsubscribe,
	}
	s.sdk = sdk.NewServer(impl, sdkOpts)
	if !cfg.AllowLegacyClients {
		s.sdk.AddReceivingMiddleware(pinProtocolMiddleware)
	}
	s.svc.OnReset(s.RotateCursors)
	s.svc.OnReset(s.reloadAuth)
	s.svc.OnApply(s.reloadAuth)
	s.registerTools()
	s.registerResources()
	s.startInboxFanout()

	s.http = sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server {
		return s.sdk
	}, &sdk.StreamableHTTPOptions{
		// 2026-07-28 Streamable HTTP is accepted only when Stateless is true.
		Stateless:                    true,
		Logger:                       logger,
		MaxRequestBodyBytes:          maxBody,
		PropagateRequestCancellation: true,
		DisableLocalhostProtection:   true,
	})
	return s, nil
}

// Handler returns the Streamable HTTP adapter. Mount it at /mcp.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

// Close marks the adapter stopped and ends inbox notify fan-out.
func (s *Server) Close() {
	s.closed.Store(true)
	if s.inboxCancel != nil {
		s.inboxCancel()
		s.inboxCancel = nil
	}
}

func (s *Server) startInboxFanout() {
	// One Subscribe for HTTP and stdio: ResourceUpdated is URI-only.
	ch, cancel := s.svc.Subscribe(context.Background(), app.Actor{ID: "mcp", Class: "system", Transport: "mcp"}, 16)
	s.inboxCancel = cancel
	go func() {
		for range ch {
			_ = s.sdk.ResourceUpdated(context.Background(), &sdk.ResourceUpdatedNotificationParams{URI: resourceFlows})
		}
	}()
}

func (s *Server) onSubscribe(ctx context.Context, req *sdk.SubscribeRequest) error {
	uri := ""
	if req != nil && req.Params != nil {
		uri = req.Params.URI
	}
	return s.authorizeResource(s.actorFrom(ctx), uri)
}

func (s *Server) onUnsubscribe(context.Context, *sdk.UnsubscribeRequest) error {
	return nil
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
	reqID := requestID(r)
	w.Header().Set(headerRequestID, reqID)

	if s.closed.Load() {
		writeRPC(w, http.StatusServiceUnavailable, domainerr.Internal("server closed"))
		return
	}

	if err := checkOrigin(r.Header.Get(headerOrigin), s.cfg.AllowedOrigins); err != nil {
		writeRPC(w, http.StatusForbidden, err)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeRPC(w, http.StatusMethodNotAllowed, domainerr.MethodNotAllowed("method not allowed"))
		return
	}

	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		writeRPC(w, http.StatusTooManyRequests, domainerr.RateLimited("too many concurrent management requests"))
		return
	}
	if err := s.rate.allow(r.RemoteAddr); err != nil {
		writeRPC(w, http.StatusTooManyRequests, err)
		return
	}

	ctx := r.Context()
	var cancel context.CancelFunc
	if s.timeout > 0 && !isLongRequest(r) {
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	ctx = context.WithValue(ctx, ctxRequestID, reqID)
	r = r.WithContext(ctx)

	defer func() {
		if rec := recover(); rec != nil {
			writeRPC(w, http.StatusInternalServerError, domainerr.Internal("internal error"))
		}
	}()

	if !s.cfg.AllowLegacyClients {
		if err := validateProtocolVersion(r); err != nil {
			writeRPC(w, http.StatusBadRequest, err)
			return
		}
	}

	actor, err := s.authenticate(r)
	if err != nil {
		status := http.StatusUnauthorized
		if de, ok := domainerr.As(err); ok && de.Code == domainerr.CodeForbidden {
			status = http.StatusForbidden
		}
		writeRPC(w, status, err)
		return
	}
	r = r.WithContext(withActor(r.Context(), actor))

	if strings.TrimSpace(r.Header.Get(headerMethod)) == methodListen {
		var ok bool
		r, ok = s.enforceListenPin(w, r)
		if !ok {
			return
		}
	}

	s.http.ServeHTTP(w, r)
}

func isLongRequest(r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get(headerMethod)) == methodListen {
		return true
	}
	return strings.TrimSpace(r.Header.Get(headerName)) == toolWait
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

func withActor(ctx context.Context, a app.Actor) context.Context {
	return context.WithValue(ctx, ctxActor, a)
}

func (s *Server) actorFrom(ctx context.Context) app.Actor {
	a, _ := ctx.Value(ctxActor).(app.Actor)
	if a.ID != "" || a.Class != "" {
		if a.Transport == "" {
			a.Transport = "mcp"
		}
		return a
	}
	if s != nil && s.cfg.FixedActor != nil {
		out := *s.cfg.FixedActor
		if out.Transport == "" {
			out.Transport = "mcp"
		}
		return out
	}
	if a.Transport == "" {
		a.Transport = "mcp"
	}
	if a.ID == "" {
		a.ID = "anonymous"
		a.Class = "administrator"
	}
	return a
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
		// Keep the previous verifier on a failed secret reread.
		return
	}
	// Do not swap in an allow-all / empty-bearer index; keep the live verifier.
	if err := next.RequireListen(); err != nil {
		return
	}
	s.cfg.Auth.Replace(next)
}

package rest

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/auth"
	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/observability"
)

func actorOf(p auth.Principal, transport string) app.Actor {
	return app.Actor{
		ID:        p.ID,
		Class:     p.Class,
		Role:      p.Role,
		Scopes:    append([]string(nil), p.Scopes...),
		Transport: transport,
	}
}

func (s *Server) authenticate(r *http.Request, skip bool) (app.Actor, error) {
	if skip {
		return app.Actor{ID: "probe", Class: "startup", Transport: "rest"}, nil
	}
	// Nil Auth is deny-all. Allow-all is not a 1.0 posture.
	if s.cfg.Auth == nil {
		s.observeAuthFailure("denied")
		return app.Actor{}, domainerr.Unauthenticated("authentication required")
	}

	hdr := strings.TrimSpace(r.Header.Get("Authorization"))
	if hdr == "" {
		s.observeAuthFailure("missing")
		return app.Actor{}, domainerr.Unauthenticated("authentication required")
	}
	p, err := s.cfg.Auth.Authenticate(auth.Request{
		Authorization: hdr,
		RemoteAddr:    r.RemoteAddr,
	})
	if err != nil {
		s.observeAuthFailure("invalid")
		return app.Actor{}, err
	}
	if s.logger != nil {
		s.logger.Log(observability.Record{
			Event:     observability.EventAuthSuccess,
			Component: "rest",
			RequestID: r.Header.Get(headerRequestID),
			Result:    "ok",
		})
	}
	return actorOf(p, "rest"), nil
}

func (s *Server) observeAuthFailure(reason string) {
	if s == nil {
		return
	}
	reason = observability.AuthFailureReason(reason)
	if s.metrics != nil {
		s.metrics.Inc(observability.MetricAuthFailuresTotal, map[string]string{"reason": reason}, 1)
	}
	if s.logger != nil {
		s.logger.Log(observability.Record{
			Event:     observability.EventAuthFailure,
			Component: "rest",
			Result:    reason,
			ErrorCode: string(domainerr.CodeUnauthenticated),
		})
	}
}

func (s *Server) authorize(_ *http.Request, actor app.Actor, cap capabilities.Capability) error {
	if s.cfg.Auth == nil {
		return domainerr.Unauthenticated("authentication required")
	}
	return auth.AuthorizeScopes(actor.Scopes, cap.RequiredScopes)
}

type limiter struct {
	disabled bool
	rate     float64
	burst    float64
	mu       sync.Mutex
	buckets  map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(rate, burst float64) *limiter {
	if rate < 0 {
		return &limiter{disabled: true}
	}
	if rate == 0 {
		rate = float64(config.DefaultRequestsPerSecond)
	}
	if burst == 0 {
		burst = float64(config.DefaultBurst)
	}
	return &limiter{rate: rate, burst: burst, buckets: map[string]*bucket{}}
}

func (l *limiter) allow(remote string) error {
	if l == nil || l.disabled {
		return nil
	}
	key := remote
	if host, _, err := net.SplitHostPort(remote); err == nil {
		key = host
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evictIdleLocked(now)
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return domainerr.RateLimited("too many management requests")
	}
	b.tokens--
	return nil
}

func (l *limiter) evictIdleLocked(now time.Time) {
	if l == nil || len(l.buckets) == 0 {
		return
	}
	idleFor := 30 * time.Second
	if l.rate > 0 {
		refill := time.Duration(float64(time.Second) * (l.burst / l.rate) * 4)
		if refill > idleFor {
			idleFor = refill
		}
	}
	for k, b := range l.buckets {
		if now.Sub(b.last) > idleFor {
			delete(l.buckets, k)
		}
	}
}

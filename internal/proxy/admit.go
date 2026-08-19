package proxy

import (
	"net"
	"net/netip"
	"sync"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

type admitErr string

func (e admitErr) Error() string { return string(e) }

const errTooManySessions admitErr = "too many sessions"

type gate struct {
	mu       sync.Mutex
	sessions int
	perIP    map[netip.Addr]int
	inflight int
}

func newGate() *gate {
	return &gate{perIP: make(map[netip.Addr]int)}
}

func (g *gate) acquire(ip netip.Addr, ad model.AdmissionSpec) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if ad.MaxSessions > 0 && g.sessions >= ad.MaxSessions {
		return errTooManySessions
	}
	if ip.IsValid() && ad.MaxSessionsPerIP > 0 && g.perIP[ip] >= ad.MaxSessionsPerIP {
		return errTooManySessions
	}
	if ad.MaxInFlight > 0 && g.inflight >= ad.MaxInFlight {
		return errTooManySessions
	}
	g.sessions++
	g.inflight++
	if ip.IsValid() {
		g.perIP[ip]++
	}
	return nil
}

func (g *gate) inUse() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sessions
}

func (s *Server) sessionCount() int {
	if s == nil {
		return 0
	}
	return s.gate.inUse()
}

func (g *gate) release(ip netip.Addr) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sessions > 0 {
		g.sessions--
	}
	if g.inflight > 0 {
		g.inflight--
	}
	if ip.IsValid() {
		n := g.perIP[ip] - 1
		if n <= 0 {
			delete(g.perIP, ip)
		} else {
			g.perIP[ip] = n
		}
	}
}

func clientIP(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

package main

import (
	"crypto/tls"
	"net"
	"sync"
)

// resetListener keeps the HTTP server and in-flight requests alive while its
// Reset-only TCP bind and TLS identity change. Retired accept calls retry.
type resetListener struct {
	mu        sync.Mutex
	raw       net.Listener
	tlsConfig *tls.Config
	closed    bool
}

func (l *resetListener) Accept() (net.Conn, error) {
	for {
		l.mu.Lock()
		raw := l.raw
		l.mu.Unlock()
		c, err := raw.Accept()
		l.mu.Lock()
		retired := raw != l.raw
		cfg, closed := l.tlsConfig, l.closed
		l.mu.Unlock()
		if retired {
			if c != nil {
				_ = c.Close()
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		if closed {
			_ = c.Close()
			return nil, net.ErrClosed
		}
		if cfg != nil {
			return tls.Server(c, cfg), nil
		}
		return c, nil
	}
}
func (l *resetListener) Addr() net.Addr { l.mu.Lock(); defer l.mu.Unlock(); return l.raw.Addr() }
func (l *resetListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return l.raw.Close()
}
func (l *resetListener) replace(raw net.Listener, cfg *tls.Config) {
	l.mu.Lock()
	old := l.raw
	if raw != nil {
		l.raw = raw
	}
	l.tlsConfig = cfg
	l.mu.Unlock()
	if raw != nil {
		_ = old.Close()
	}
}

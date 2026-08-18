package proxy

import (
	"context"
	"fmt"
	"net"
	"time"
)

// dialTCP is the only production Dial site. addr must be host:port where
// host is already a literal IP so Resolver: nil cannot rebind the name.
func dialTCP(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("proxy: dial addr: %w", err)
	}
	if net.ParseIP(host) == nil {
		return nil, fmt.Errorf("proxy: refusing hostname dial %q (must be pinned IP)", addr)
	}
	if network == "" {
		network = "tcp"
	}
	d := net.Dialer{
		Timeout:  timeout,
		Resolver: nil, // no second lookup; addr is a literal IP
	}
	return d.DialContext(ctx, network, addr)
}

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

// listenEphemeralTCP is the only production BIND listen site (D58/D68).
// controlIP is the SOCKS control LocalAddr host — never ":0" / 0.0.0.0 / ::.
func listenEphemeralTCP(controlIP net.IP) (net.Listener, error) {
	if err := checkBindListenIP(controlIP); err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(controlIP.String(), "0")
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return nil, fmt.Errorf("proxy: refusing wildcard BIND listen")
	}
	return net.Listen("tcp", addr)
}

// dialUDP is the only production UDP Dial site (D68). addr must be a
// literal IP:port so Resolver: nil cannot rebind the name.
func dialUDP(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("proxy: dial addr: %w", err)
	}
	if net.ParseIP(host) == nil {
		return nil, fmt.Errorf("proxy: refusing hostname dial %q (must be pinned IP)", addr)
	}
	if network == "" {
		network = "udp"
	}
	d := net.Dialer{
		Timeout:  timeout,
		Resolver: nil, // no second lookup; addr is a literal IP
	}
	return d.DialContext(ctx, network, addr)
}

// listenEphemeralUDP is the only production UDP ASSOCIATE listen site (D59/D68).
// controlIP is the SOCKS control LocalAddr host — never ":0" / 0.0.0.0 / ::.
func listenEphemeralUDP(controlIP net.IP) (net.PacketConn, error) {
	if err := checkBindListenIP(controlIP); err != nil {
		return nil, err
	}
	network := "udp6"
	if v4 := controlIP.To4(); v4 != nil {
		controlIP = v4
		network = "udp4"
	}
	return net.ListenUDP(network, &net.UDPAddr{IP: controlIP, Port: 0})
}

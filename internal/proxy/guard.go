package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// Resolver is the single LookupIP site. Production uses net.DefaultResolver.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type defaultResolver struct{}

func (defaultResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, network, host)
}

var (
	errTargetDenied = errors.New("target_denied")
	errDNS          = errors.New("dns")
)

func mustCIDR(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

var (
	metadataCIDRs = []netip.Prefix{
		mustCIDR("169.254.169.254/32"),
		mustCIDR("fd00:ec2::254/128"),
	}
	linkLocalCIDRs = []netip.Prefix{
		mustCIDR("169.254.0.0/16"),
		mustCIDR("fe80::/10"),
	}
)

// resolved is a name (or literal) that passed every A/AAAA CIDR check.
type resolved struct {
	Host     string
	Port     string
	Selected net.IP
	All      []net.IP
}

// resolveThenGuard implements D16. If any resolved address is denied, the
// whole name is rejected. Dial is not performed here.
func resolveThenGuard(ctx context.Context, res Resolver, targets model.TargetsSpec, host, port string) (resolved, error) {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" || port == "" {
		return resolved{}, fmt.Errorf("%w: empty authority", errTargetDenied)
	}
	if res == nil {
		res = defaultResolver{}
	}

	var addrs []net.IP
	if ip := net.ParseIP(host); ip != nil {
		addrs = []net.IP{ip}
	} else {
		if matchHostList(targets.DenyHosts, host) {
			return resolved{}, fmt.Errorf("%w: denyHosts", errTargetDenied)
		}
		if len(targets.AllowHosts) > 0 && !matchHostList(targets.AllowHosts, host) {
			return resolved{}, fmt.Errorf("%w: allowHosts", errTargetDenied)
		}
		looked, err := res.LookupIP(ctx, "ip", host)
		if err != nil || len(looked) == 0 {
			return resolved{}, fmt.Errorf("%w: %v", errDNS, err)
		}
		addrs = looked
	}

	var allowed []net.IP
	for _, addr := range addrs {
		if denyIP(targets, addr) {
			return resolved{}, fmt.Errorf("%w: %s", errTargetDenied, addr)
		}
		allowed = append(allowed, addr)
	}
	if len(allowed) == 0 {
		return resolved{}, fmt.Errorf("%w: no allowed address", errTargetDenied)
	}
	return resolved{
		Host:     host,
		Port:     port,
		Selected: pickAddr(allowed),
		All:      allowed,
	}, nil
}

func denyIP(t model.TargetsSpec, ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if t.DenyCloudMetadata && inPrefixes(addr, metadataCIDRs) {
		return true
	}
	if t.DenyLinkLocal && inPrefixes(addr, linkLocalCIDRs) {
		return true
	}
	if addr.IsLoopback() && !t.AllowLoopback {
		return true
	}
	return false
}

func inPrefixes(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// pickAddr is stable: IPv6 if present, else IPv4.
func pickAddr(addrs []net.IP) net.IP {
	for _, a := range addrs {
		if a != nil && a.To4() == nil {
			return a
		}
	}
	return addrs[0]
}

func matchHostList(patterns []string, host string) bool {
	for _, p := range patterns {
		if matchHost(p, host) {
			return true
		}
	}
	return false
}

func matchHost(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if pattern == "" || host == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suf := pattern[1:] // ".suffix"
		return strings.HasSuffix(host, suf) && host != suf[1:]
	}
	return pattern == host
}

func splitAuthority(authority, defaultPort string) (host, port string, err error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", "", errors.New("empty authority")
	}
	if h, p, e := net.SplitHostPort(authority); e == nil {
		return h, p, nil
	}
	// Bracketed IPv6 without a port: "[::1]" (url.URL.Host for http://[::1]/).
	if inner, ok := unbracketIP(authority); ok {
		if defaultPort == "" {
			return "", "", fmt.Errorf("missing port")
		}
		return inner, defaultPort, nil
	}
	if net.ParseIP(authority) != nil {
		if defaultPort == "" {
			return "", "", fmt.Errorf("missing port")
		}
		return authority, defaultPort, nil
	}
	if strings.Contains(authority, ":") {
		// Ambiguous IPv6-without-brackets-and-port. Require [ip]:port.
		return "", "", fmt.Errorf("missing port")
	}
	if defaultPort == "" {
		return "", "", fmt.Errorf("missing port")
	}
	return authority, defaultPort, nil
}

func unbracketIP(s string) (string, bool) {
	if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' {
		return "", false
	}
	inner := s[1 : len(s)-1]
	if net.ParseIP(inner) == nil {
		return "", false
	}
	return inner, true
}

// originHost is the RFC 9110 Host value sent upstream. IPv6 literals stay
// bracketed; default port 80 is omitted.
func originHost(host, port string) string {
	if port != "" && port != "80" {
		return net.JoinHostPort(host, port)
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

func pinnedAddr(ip net.IP, port string) string {
	return net.JoinHostPort(ip.String(), port)
}

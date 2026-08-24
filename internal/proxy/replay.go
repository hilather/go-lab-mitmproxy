package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/httputilx"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
	"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm"
)

// Replay re-issues stored as an origin-form request. It Dials the origin via
// the same resolve-then-guard path as live traffic, ignores HTTP_PROXY, and
// never hairpins listeners.proxy.address (D21).
func (s *Server) Replay(ctx context.Context, stored *model.Flow) (*model.Flow, error) {
	if s == nil {
		return nil, domainerr.Internal("proxy is not running")
	}
	if stored == nil {
		return nil, domainerr.ValidationFailed("flow is required",
			domainerr.FieldViolation{Path: "id", Code: "required", Message: "flow is required"})
	}
	if err := rejectReplayable(stored); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	spec := s.liveSpec()
	scheme := strings.ToLower(strings.TrimSpace(stored.Scheme))
	if scheme == "" {
		scheme = "http"
	}
	defaultPort := "80"
	if scheme == "https" {
		defaultPort = "443"
	}
	authority := stored.Host
	if authority == "" {
		if u, err := url.Parse(stored.URL); err == nil {
			authority = u.Host
		}
	}
	host, port, err := splitAuthority(authority, defaultPort)
	if err != nil {
		return nil, domainerr.ValidationFailed("invalid host",
			domainerr.FieldViolation{Path: "host", Code: "invalid_value", Message: "flow host is not a valid authority"})
	}
	res, err := resolveThenGuard(ctx, s.resolver, spec.Proxy.Targets, host, port)
	if err != nil {
		if isDNS(err) {
			return nil, domainerr.Internal("dns lookup failed")
		}
		return nil, domainerr.TargetDenied("target denied")
	}
	if s.isHairpin(res, spec) {
		return nil, domainerr.TargetDenied("replay must not hairpin the proxy listener")
	}

	out, err := replayRequest(ctx, stored, res, host, port, scheme)
	if err != nil {
		return nil, err
	}
	started := time.Now().UTC()
	resp, err := s.roundTripReplay(ctx, out, res, host, scheme, spec)
	if err != nil {
		f := replayFlow(stored, host, scheme, 0, "upstream", started, nil, nil)
		s.captureReplay(f)
		return nil, domainerr.Internal("upstream request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	max := spec.Store.MaxBodyBytes
	if max <= 0 {
		max = defaultMaxBodyBytes
	}
	respCap := &cappedWriter{max: int(max)}
	_, _ = io.Copy(respCap, resp.Body)
	f := replayFlow(stored, host, scheme, resp.StatusCode, "", started, resp, respCap)
	s.captureReplay(f)
	if s.inbox != nil && f.ID != "" {
		got, gerr := s.inbox.Get(f.ID)
		if gerr == nil {
			return got, nil
		}
	}
	return f, nil
}

func rejectReplayable(stored *model.Flow) error {
	if strings.EqualFold(stored.Method, http.MethodConnect) || stored.Protocol == model.FlowProtocolConnect {
		return domainerr.ValidationFailed("CONNECT flows cannot be replayed",
			domainerr.FieldViolation{Path: "protocol", Code: "invalid_value", Message: "CONNECT-metadata flows cannot be replayed"})
	}
	if stored.Protocol == model.FlowProtocolWebSocket {
		return domainerr.ValidationFailed("websocket flows cannot be replayed",
			domainerr.FieldViolation{Path: "protocol", Code: "invalid_value", Message: "websocket flows cannot be replayed"})
	}
	if stored.Request.Truncated {
		return domainerr.ValidationFailed("truncated request cannot be replayed",
			domainerr.FieldViolation{Path: "request", Code: "invalid_value", Message: "truncated request cannot be replayed"})
	}
	return nil
}

func (s *Server) liveSpec() model.Spec {
	if s.snaps != nil {
		if snap := s.snaps.Load(); snap != nil {
			return snap.Spec()
		}
	}
	return s.specNow()
}

func (s *Server) liveAuthority() *tlsmitm.Authority {
	if s.snaps != nil {
		if snap := s.snaps.Load(); snap != nil && snap.CA != nil {
			return snap.CA
		}
	}
	return s.auth
}

func (s *Server) isHairpin(res resolved, spec model.Spec) bool {
	target := pinnedAddr(res.Selected, res.Port)
	var candidates []string
	if addr := s.Addr(); addr != nil {
		candidates = append(candidates, addr.String())
	}
	if spec.Listeners.Proxy.Address != "" {
		candidates = append(candidates, spec.Listeners.Proxy.Address)
	}
	if addr := s.OrigDestAddr(); addr != nil {
		candidates = append(candidates, addr.String())
	}
	if spec.Listeners.OriginalDestination.Address != "" {
		candidates = append(candidates, spec.Listeners.OriginalDestination.Address)
	}
	candidates = append(candidates, s.liveBindAddrs()...)
	for _, c := range candidates {
		if sameEndpoint(c, target) {
			return true
		}
	}
	return false
}

func sameEndpoint(a, b string) bool {
	ah, ap, err := splitListenHostPort(a)
	if err != nil {
		return false
	}
	bh, bp, err := splitListenHostPort(b)
	if err != nil {
		return false
	}
	if ap != bp {
		return false
	}
	if unspecifiedHost(ah) && unspecifiedHost(bh) {
		return true
	}
	// Wildcard / unspecified bind (:8888, 0.0.0.0, ::) hairpins every
	// local unicast on that port (lab overlay publishes :8888).
	if unspecifiedHost(ah) {
		return isLocalIP(bh)
	}
	if unspecifiedHost(bh) {
		return isLocalIP(ah)
	}
	ai := net.ParseIP(ah)
	bi := net.ParseIP(bh)
	if ai != nil && bi != nil {
		return ai.Equal(bi)
	}
	return strings.EqualFold(ah, bh)
}

// splitListenHostPort accepts "host:port", ":port", and "[::]:port".
func splitListenHostPort(addr string) (host, port string, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", errors.New("empty listen address")
	}
	return net.SplitHostPort(addr)
}

func unspecifiedHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" || h == "*" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsUnspecified()
}

func isLocalIP(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP == nil {
			continue
		}
		if n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

func replayRequest(ctx context.Context, stored *model.Flow, res resolved, host, port, scheme string) (*http.Request, error) {
	u := &url.URL{
		Scheme: scheme,
		Host:   pinnedAddr(res.Selected, res.Port),
		Path:   "/",
	}
	if stored.URL != "" {
		if pu, err := url.Parse(stored.URL); err == nil {
			if pu.Path != "" {
				u.Path = pu.Path
			}
			u.RawPath = pu.RawPath
			u.RawQuery = pu.RawQuery
		}
	}
	if u.Path == "" {
		u.Path = "/"
	}
	var body io.Reader
	if len(stored.Request.Body) > 0 {
		body = bytes.NewReader(stored.Request.Body)
	}
	method := stored.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, domainerr.ValidationFailed("invalid replay request",
			domainerr.FieldViolation{Path: "url", Code: "invalid_value", Message: "could not build origin request"})
	}
	req.RequestURI = ""
	req.URL = u
	if scheme == "https" {
		req.Host = originHostTLS(host, port)
	} else {
		req.Host = originHost(host, port)
	}
	if auth := headerValue(stored.Request.Headers, ":authority"); auth != "" {
		req.Host = auth
	}
	for _, h := range stored.Request.Headers {
		if h.Name == "" || isPseudoHeaderName(h.Name) {
			continue
		}
		req.Header.Add(h.Name, h.Value)
	}
	stripLeadingColonHeaders(req.Header)
	httputilx.PrepareRequest(req.Header)
	return req, nil
}

func originHostTLS(host, port string) string {
	if port != "" && port != "443" {
		return net.JoinHostPort(host, port)
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

func (s *Server) roundTripReplay(ctx context.Context, req *http.Request, res resolved, host, scheme string, spec model.Spec) (*http.Response, error) {
	if scheme != "https" {
		// Process Transport already has Proxy: nil (HTTP_PROXY ignored).
		return s.tr.RoundTrip(req)
	}
	conn, err := s.dialPinned(ctx, "tcp", pinnedAddr(res.Selected, res.Port))
	if err != nil {
		return nil, err
	}
	cfg := replayTLSConfig(s.liveAuthority(), host, spec)
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	proto := http1Only()
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return tlsConn, nil
		},
		ForceAttemptHTTP2:  false,
		DisableCompression: true,
		TLSNextProto:       map[string]func(string, *tls.Conn) http.RoundTripper{},
		Protocols:          proto,
	}
	// After handshake, send origin-form over the TLS conn as HTTP/1.1.
	req = req.Clone(ctx)
	req.URL.Scheme = "http"
	resp, err := tr.RoundTrip(req)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return resp, nil
}

func replayTLSConfig(auth *tlsmitm.Authority, sni string, spec model.Spec) *tls.Config {
	if auth != nil {
		return auth.UpstreamConfig(sni)
	}
	return &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{tlsmitm.ALPN},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: spec.TLS.Upstream.InsecureSkipVerify,
	}
}

func replayFlow(stored *model.Flow, host, scheme string, status int, ferr string, started time.Time, resp *http.Response, respCap *cappedWriter) *model.Flow {
	state := model.FlowStateCompleted
	if ferr != "" {
		state = model.FlowStateError
	}
	u := stored.URL
	if u == "" {
		u = scheme + "://" + host + "/"
	}
	f := &model.Flow{
		StartedAt:   started,
		CompletedAt: time.Now().UTC(),
		State:       state,
		Method:      stored.Method,
		URL:         u,
		Host:        host,
		Scheme:      scheme,
		Protocol:    model.FlowProtocolHTTP11,
		Status:      status,
		Error:       ferr,
		Request:     stored.Request,
	}
	if resp != nil {
		f.Response.Headers = headersFrom(resp.Header)
	}
	if respCap != nil {
		f.Response.Body = respCap.buf
		f.Response.Size = len(respCap.buf)
		f.Response.Truncated = respCap.truncated
		f.Truncated = f.Truncated || respCap.truncated
	}
	return f
}

func (s *Server) captureReplay(f *model.Flow) {
	if s == nil || f == nil {
		return
	}
	if s.inbox != nil {
		res, err := s.inbox.Insert(s.ctx, s.inbox.Epoch(), f)
		if err == nil {
			f.ID = res.ID
			return
		}
		if errors.Is(err, store.ErrFull) {
			s.metrics.storeFullInc()
		}
	}
	s.capture(f, nil)
}

package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

var errOrigDestUnsupported = errors.New("proxy: original destination is unavailable")

type connKind int

const (
	kindProxy connKind = iota
	kindOrigDest
)

type origDestCtxKey struct{}

type origDestMeta struct {
	IP       net.IP
	Port     string
	HostPort string
}

// taggedConn carries recovered dest into http.Server via ConnContext (D55).
type taggedConn struct {
	net.Conn
	kind     connKind
	origDest origDestMeta
}

func (c *taggedConn) CloseWrite() error {
	if c == nil {
		return net.ErrClosed
	}
	type closer interface {
		CloseWrite() error
	}
	if cw, ok := c.Conn.(closer); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

func makeOrigDest(ip net.IP, port int) (origDestMeta, error) {
	if ip == nil {
		return origDestMeta{}, errOrigDestUnsupported
	}
	if port <= 0 || port > 65535 {
		return origDestMeta{}, errOrigDestUnsupported
	}
	ip = append(net.IP(nil), ip...)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	ps := strconv.Itoa(port)
	return origDestMeta{IP: ip, Port: ps, HostPort: net.JoinHostPort(ip.String(), ps)}, nil
}

func origDestFromContext(req *http.Request) (origDestMeta, bool) {
	if req == nil {
		return origDestMeta{}, false
	}
	dest, ok := req.Context().Value(origDestCtxKey{}).(origDestMeta)
	if !ok || dest.IP == nil || dest.Port == "" {
		return origDestMeta{}, false
	}
	return dest, true
}

func (s *Server) connContext(ctx context.Context, c net.Conn) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	t, ok := c.(*taggedConn)
	if !ok || t == nil || t.kind != kindOrigDest {
		return ctx
	}
	return context.WithValue(ctx, origDestCtxKey{}, t.origDest)
}

func (s *Server) originalDst(c net.Conn) (origDestMeta, error) {
	if s != nil && s.origDestFn != nil {
		ip, port, err := s.origDestFn(c)
		if err != nil {
			return origDestMeta{}, err
		}
		return makeOrigDest(ip, port)
	}
	ip, port, err := getOriginalDst(c)
	if err != nil {
		return origDestMeta{}, err
	}
	return makeOrigDest(ip, port)
}

func (s *Server) dispatchOrigDest(c net.Conn) {
	if c == nil {
		return
	}
	dest, err := s.originalDst(c)
	if err != nil {
		s.untrackDispatch(c)
		s.metrics.reject("origdest")
		_ = c.Close()
		return
	}
	if s.isDirectConnect(dest) {
		s.untrackDispatch(c)
		s.metrics.reject("origdest")
		_ = c.Close()
		return
	}
	spec := withSpecDefaults(s.liveSpec())
	res, err := resolveThenGuard(s.ctx, s.resolver, spec.Proxy.Targets, dest.IP.String(), dest.Port)
	if err != nil {
		s.untrackDispatch(c)
		s.metrics.reject("target_denied")
		_ = c.Close()
		return
	}
	if s.isHairpin(res, spec) {
		s.untrackDispatch(c)
		s.metrics.reject("origdest")
		_ = c.Close()
		return
	}

	ht := spec.Proxy.Admission.HeaderTimeout
	if ht <= 0 {
		ht = defaultHeaderTimeout
	}
	_ = c.SetReadDeadline(time.Now().Add(ht))
	pc, b, err := peekReplay(c, 1)
	_ = c.SetReadDeadline(time.Time{})
	s.untrackDispatch(c)
	if err != nil || len(b) == 0 {
		_ = c.Close()
		return
	}
	if b[0] == 0x04 || b[0] == 0x05 {
		s.closeSOCKS(pc)
		return
	}
	if b[0] == 0x16 {
		s.serveOrigDestTLS(pc, dest, ht)
		return
	}
	httpLn := s.httpLn
	if httpLn == nil {
		_ = pc.Close()
		return
	}
	httpLn.Push(&taggedConn{Conn: pc, kind: kindOrigDest, origDest: dest})
}

// isDirectConnect is D34: dest port equals the orig-dest listen port and dest
// IP is local/unspecified (Docker DNAT to :8890).
func (s *Server) isDirectConnect(dest origDestMeta) bool {
	listen := s.OrigDestAddr()
	if listen == nil || dest.IP == nil || dest.Port == "" {
		return false
	}
	_, lp, err := net.SplitHostPort(listen.String())
	if err != nil || dest.Port != lp {
		return false
	}
	return dest.IP.IsUnspecified() || dest.IP.IsLoopback() || isLocalIP(dest.IP.String())
}

func (s *Server) serveOrigDestHTTP(w http.ResponseWriter, req *http.Request, dest origDestMeta, sess *ruleSession) {
	started := time.Now()
	if sess == nil {
		sess = s.beginSession()
	}
	sess.via = "original-dest"
	sess.originalDest = dest.HostPort

	guardCtx, guardCancel := s.upstreamCtxSess(req.Context(), sess)
	res, err := resolveThenGuard(guardCtx, s.resolver, sess.spec.Proxy.Targets, dest.IP.String(), dest.Port)
	guardCancel()
	if err != nil {
		s.rejectResolve(w, req, dest.IP.String(), err, sess)
		return
	}
	if s.isHairpin(res, sess.spec) || s.isDirectConnect(dest) {
		s.metrics.reject("origdest")
		s.capture(s.flowFromReq(req, dest.IP.String(), "http", http.StatusForbidden, string(domainerr.CodeTargetDenied), started), sess)
		writeProxyError(w, http.StatusForbidden, domainerr.CodeTargetDenied, "target denied", "")
		return
	}
	host, port := s.origDestCaptureHost(req, dest, sess.spec)
	s.forwardOriginHTTP(w, req, res, host, port, started, sess)
}

func (s *Server) origDestCaptureHost(req *http.Request, dest origDestMeta, spec model.Spec) (host, port string) {
	host, port = dest.IP.String(), dest.Port
	if req == nil {
		return host, port
	}
	raw := strings.TrimSpace(req.Host)
	if raw == "" && req.URL != nil {
		raw = req.URL.Host
	}
	if raw == "" {
		return host, port
	}
	h, p, err := splitAuthority(raw, dest.Port)
	if err != nil || h == "" {
		return host, port
	}
	if s.isListenAuthority(h, p, spec) {
		return dest.IP.String(), dest.Port
	}
	return h, p
}

func (s *Server) isListenAuthority(h, p string, spec model.Spec) bool {
	target := net.JoinHostPort(h, p)
	var cands []string
	if a := s.Addr(); a != nil {
		cands = append(cands, a.String())
	}
	if a := s.OrigDestAddr(); a != nil {
		cands = append(cands, a.String())
	}
	if spec.Listeners.Proxy.Address != "" {
		cands = append(cands, spec.Listeners.Proxy.Address)
	}
	if spec.Listeners.OriginalDestination.Address != "" {
		cands = append(cands, spec.Listeners.OriginalDestination.Address)
	}
	for _, c := range cands {
		if sameEndpoint(c, target) {
			return true
		}
	}
	return false
}

func (s *Server) serveOrigDestTLS(c net.Conn, dest origDestMeta, headerTO time.Duration) {
	if c == nil {
		return
	}
	started := time.Now()
	sess := s.beginSession()
	sess.via = "original-dest"
	sess.originalDest = dest.HostPort
	ip := clientIP(addrString(c.RemoteAddr()))
	if err := s.gate.acquire(ip, sess.spec.Proxy.Admission); err != nil {
		s.metrics.reject("admission")
		_ = c.Close()
		return
	}
	defer s.gate.release(ip)
	s.metrics.accept()

	s.beginHijacked()
	defer s.endHijacked()
	s.track(c)
	defer s.untrack(c)
	defer func() { _ = c.Close() }()

	if headerTO <= 0 {
		headerTO = defaultHeaderTimeout
	}
	_ = c.SetReadDeadline(time.Now().Add(headerTO))
	pc, hello, err := readClientHello(c, 16<<10)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		s.failIntercept(nil, dest.IP.String(), started, "tls_handshake", sess)
		return
	}
	c = pc

	sni := hello.ServerName
	connectHost := sni
	if connectHost == "" {
		connectHost = dest.IP.String()
	}
	intercept, failHS, denied := origDestInterceptDecision(sess.spec.TLS, sni, dest.Port)
	if failHS {
		s.failIntercept(nil, connectHost, started, "tls_handshake", sess)
		return
	}
	if denied {
		s.metrics.reject("target_denied")
		s.capture(connectErrFlow(nil, connectHost, model.FlowStateError, string(domainerr.CodeTargetDenied), started), sess)
		return
	}

	ctx, cancel := context.WithTimeout(s.ctx, sess.spec.Proxy.Admission.UpstreamTimeout)
	defer cancel()
	res, err := resolveThenGuard(ctx, s.resolver, sess.spec.Proxy.Targets, dest.IP.String(), dest.Port)
	if err != nil {
		s.metrics.reject("target_denied")
		s.capture(connectErrFlow(nil, dest.IP.String(), model.FlowStateError, string(domainerr.CodeTargetDenied), started), sess)
		return
	}
	if s.isHairpin(res, sess.spec) {
		s.metrics.reject("origdest")
		s.capture(connectErrFlow(nil, dest.IP.String(), model.FlowStateError, string(domainerr.CodeTargetDenied), started), sess)
		return
	}

	up, err := s.dialPinnedTO(ctx, "tcp", pinnedAddr(res.Selected, res.Port), sess.spec.Proxy.Admission.DialTimeout)
	if err != nil {
		s.capture(connectErrFlow(nil, dest.IP.String(), model.FlowStateError, "dial", started), sess)
		return
	}
	s.track(up)
	defer s.untrack(up)
	defer func() { _ = up.Close() }()

	if intercept {
		s.serveInterceptConn(c, nil, up, interceptMeta{
			ConnectHost:  connectHost,
			Port:         dest.Port,
			Res:          res,
			Started:      started,
			Via:          "original-dest",
			OriginalDest: dest.HostPort,
		}, sess)
		return
	}
	f := connectFlow(nil, dest.IP.String(), http.StatusOK, "", started)
	f.Via = "original-dest"
	f.OriginalDest = dest.HostPort
	s.capture(f, sess)
	s.metrics.session("ok")
	s.tunnel(c, nil, up, sess.spec.Proxy.Admission)
}

func origDestInterceptDecision(tlsSpec model.TLSSpec, sni, port string) (intercept, failHandshake, denied bool) {
	if !tlsSpec.Intercept {
		return false, false, false
	}
	p, err := strconv.Atoi(port)
	if err != nil || !portListed(tlsSpec.Ports, p) {
		return false, false, false
	}
	if len(tlsSpec.Hosts) == 0 {
		return true, false, false
	}
	if sni == "" {
		return false, true, false
	}
	if matchHostList(tlsSpec.Hosts, sni) {
		return true, false, false
	}
	return false, false, true
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

func tcpConnOf(c net.Conn) *net.TCPConn {
	for c != nil {
		switch t := c.(type) {
		case *net.TCPConn:
			return t
		case *taggedConn:
			c = t.Conn
		case *peekedConn:
			c = t.Conn
		case *recordingConn:
			c = t.Conn
		default:
			return nil
		}
	}
	return nil
}

package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/http2x"
	"github.com/hilather/go-lab-mitmproxy/internal/httputilx"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// serveH2C Hijacks PRI without writing (D19), acquires once per TCP, then
// ServeConn PrefaceTail on leftover SM+SETTINGS (D61). Never returns the conn
// to http.Server. Do not enable stdlib unencrypted HTTP/2.
func (s *Server) serveH2C(w http.ResponseWriter, req *http.Request, sess *ruleSession) {
	if req == nil {
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		s.metrics.reject("http2")
		s.closeNow(w)
		return
	}
	client, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	s.beginHijacked()
	defer s.endHijacked()
	s.track(client)
	defer s.untrack(client)
	defer func() { _ = client.Close() }()

	if sess == nil {
		sess = s.beginSession()
	}
	ip := clientIP(req.RemoteAddr)
	if !ip.IsValid() && client != nil {
		ip = clientIP(addrString(client.RemoteAddr()))
	}
	if err := s.gate.acquire(ip, sess.spec.Proxy.Admission); err != nil {
		s.metrics.reject("admission")
		return
	}
	defer s.gate.release(ip)
	s.metrics.accept()

	dest, tagged := origDestFromContext(req)
	maxStreams := uint32(0)
	if n := sess.spec.Proxy.Admission.MaxConcurrentStreams; n > 0 {
		maxStreams = uint32(n)
	}
	_ = http2x.ServeConn(s.ctx, client, bufrw, http2x.ServeOpts{
		Preface:               http2x.PrefaceTail,
		MaxConcurrentStreams:  maxStreams,
		EnableConnectProtocol: sess.spec.Protocols.HTTP2.ExtendedConnect,
	}, func(ctx context.Context, in http2x.Stream) (*http.Response, []model.Header, error) {
		return s.roundTripH2C(ctx, in, sess, tagged, dest)
	}, func(ctx context.Context, in http2x.Stream) (http2x.Tunnel, error) {
		return s.h2cTunnel(ctx, in, sess, tagged)
	})
}

func (s *Server) roundTripH2C(ctx context.Context, in http2x.Stream, pinned *ruleSession, tagged bool, dest origDestMeta) (*http.Response, []model.Header, error) {
	if ctx == nil {
		ctx = s.ctx
	}
	if h2cForbidden(in) {
		return nil, nil, http2x.ErrInnerCONNECT
	}

	sess := pinned.fork()
	inner := reconstructH2Request(in)
	if inner.URL == nil {
		inner.URL = &url.URL{}
	}
	scheme := strings.ToLower(in.Scheme)
	inner.URL.Scheme = scheme
	inner.URL.Host = in.Authority
	if inner.URL.Path == "" {
		inner.URL.Path = "/"
	}
	stripLeadingColonHeaders(inner.Header)
	// captureRW is not a Hijacker; do not take serveExpectAbsolute.
	// Strip Expect and RoundTrip (never emit 100), same as cleartext.
	if inner.Header != nil {
		inner.Header.Del("Expect")
	}
	inner = inner.WithContext(ctx)

	if scheme == "https" {
		s.metrics.reject("absolute_https")
		s.capture(&model.Flow{
			Method:   in.Method,
			URL:      inner.URL.String(),
			Host:     in.Authority,
			Scheme:   "https",
			Protocol: model.FlowProtocolHTTP2,
			State:    model.FlowStateError,
			Error:    string(domainerr.CodeValidationFailed),
			Status:   http.StatusBadRequest,
			HTTP2:    &model.HTTP2Info{StreamID: in.ID},
		}, sess)
		rw := newCaptureRW()
		writeProxyError(rw, http.StatusBadRequest, domainerr.CodeValidationFailed,
			"https absolute-form is not supported", "use CONNECT")
		return rw.response(), nil, nil
	}
	if scheme != "http" || in.Authority == "" {
		rw := newCaptureRW()
		writeProxyError(rw, http.StatusBadRequest, domainerr.CodeValidationFailed,
			"absolute-form or CONNECT required", "")
		return rw.response(), nil, nil
	}

	rw := newCaptureRW()
	var result ruleResult
	if tagged {
		result = s.serveOrigDestHTTP(rw, inner, dest, sess)
	} else {
		result = s.serveAbsolute(rw, inner, sess)
	}
	if result == ruleSilentClose {
		return nil, nil, http2x.ErrSilentClose
	}
	return s.paceReturnedResponse(ctx, sess, rw.response()), nil, nil
}

// responseWriterIsClient is false for captureRW: that buffer is not the
// client hop. Throttle must wrap the returned Body so HEADERS go out
// before paced DATA (D75).
func responseWriterIsClient(w http.ResponseWriter) bool {
	if w == nil {
		return false
	}
	_, buffered := w.(*captureRW)
	return !buffered
}

// h2cTunnel is the client-facing CONNECT / :protocol handler (D62).
// Orig-dest tagged CONNECT is 400, no Dial. Nested inner CONNECT is not
// this path (innerH2Tunnel). Handshake failure is AfterAck RST/close, not a
// DATA splice (D20).
func (s *Server) h2cTunnel(ctx context.Context, in http2x.Stream, pinned *ruleSession, tagged bool) (http2x.Tunnel, error) {
	if tagged {
		return http2x.Tunnel{Status: http.StatusBadRequest}, nil
	}
	sess := pinned
	if sess == nil {
		sess = s.beginSession()
	}
	proto := strings.TrimSpace(in.Protocol)
	if proto != "" {
		if !sess.spec.Protocols.HTTP2.ExtendedConnect || !strings.EqualFold(in.Method, http.MethodConnect) || !strings.EqualFold(proto, "websocket") {
			s.metrics.reject("http2")
			return http2x.Tunnel{}, http2x.ErrInnerCONNECT
		}
		return s.h2cWebSocketTunnel(ctx, in, sess)
	}
	if !strings.EqualFold(in.Method, http.MethodConnect) {
		s.metrics.reject("http2")
		return http2x.Tunnel{}, http2x.ErrInnerCONNECT
	}
	return s.h2cConnectTunnel(ctx, in, sess)
}

func (s *Server) h2cConnectTunnel(ctx context.Context, in http2x.Stream, sess *ruleSession) (http2x.Tunnel, error) {
	started := time.Now()
	req := h2cConnectRequest(in)
	host, port, err := splitAuthority(in.Authority, "")
	if err != nil || port == "" {
		return http2x.Tunnel{Status: http.StatusBadRequest}, nil
	}
	if sess != nil && sess.spec.Proxy.HTTPAuth.Enabled && !matchHTTPAuth(req, s.httpAuthUsers(sess)) {
		s.metrics.reject("proxy_auth")
		s.capture(h2cConnectFlow(req, host, in.ID, http.StatusProxyAuthRequired, "proxy_auth", started), sess)
		return http2x.Tunnel{
			Status:  http.StatusProxyAuthRequired,
			Headers: h2cProxyAuthChallenge(sess.spec.Proxy.HTTPAuth.Realm),
		}, nil
	}
	if ctx == nil {
		ctx = s.ctx
	}
	dialCtx, cancel := context.WithTimeout(ctx, sess.spec.Proxy.Admission.UpstreamTimeout)
	defer cancel()

	res, err := resolveThenGuard(dialCtx, s.resolver, sess.spec.Proxy.Targets, host, port)
	if err != nil {
		if isDNS(err) {
			s.capture(h2cConnectFlow(req, host, in.ID, http.StatusBadGateway, "dns", started), sess)
			return http2x.Tunnel{Status: http.StatusBadGateway}, nil
		}
		s.metrics.reject("target_denied")
		s.capture(h2cConnectFlow(req, host, in.ID, http.StatusForbidden, string(domainerr.CodeTargetDenied), started), sess)
		return http2x.Tunnel{Status: http.StatusForbidden}, nil
	}

	up, err := s.dialPinnedTO(dialCtx, "tcp", pinnedAddr(res.Selected, res.Port), sess.spec.Proxy.Admission.DialTimeout)
	if err != nil {
		s.capture(h2cConnectFlow(req, host, in.ID, http.StatusBadGateway, "dial", started), sess)
		return http2x.Tunnel{Status: http.StatusBadGateway}, nil
	}
	s.track(up)

	if shouldIntercept(sess.spec.TLS, host, port) {
		return http2x.Tunnel{
			Kind:   http2x.TunnelIntercept,
			Origin: up,
			AfterAck: func(client net.Conn) {
				defer s.untrack(up)
				defer func() { _ = up.Close() }()
				if client != nil {
					defer func() { _ = client.Close() }()
				}
				s.serveInterceptConn(client, nil, up, interceptMeta{
					ConnectHost: host,
					Port:        port,
					Res:         res,
					Started:     started,
					ClientReq:   req,
					Via:         "http-proxy",
				}, sess)
			},
		}, nil
	}

	s.capture(h2cConnectFlow(req, host, in.ID, http.StatusOK, "", started), sess)
	s.metrics.session("ok")
	ad := sess.spec.Proxy.Admission
	return http2x.Tunnel{
		Kind:   http2x.TunnelRaw,
		Origin: up,
		AfterAck: func(client net.Conn) {
			defer s.untrack(up)
			defer func() { _ = up.Close() }()
			if client != nil {
				defer func() { _ = client.Close() }()
			}
			s.tunnel(client, nil, up, ad)
		},
	}, nil
}

func (s *Server) h2cWebSocketTunnel(ctx context.Context, in http2x.Stream, sess *ruleSession) (http2x.Tunnel, error) {
	started := time.Now()
	defPort := "80"
	if strings.EqualFold(in.Scheme, "https") {
		defPort = "443"
	}
	host, port, err := splitAuthority(in.Authority, defPort)
	if err != nil || host == "" {
		return http2x.Tunnel{Status: http.StatusBadRequest}, nil
	}
	if ctx == nil {
		ctx = s.ctx
	}
	dialCtx, cancel := context.WithTimeout(ctx, sess.spec.Proxy.Admission.UpstreamTimeout)
	res, err := resolveThenGuard(dialCtx, s.resolver, sess.spec.Proxy.Targets, host, port)
	if err != nil {
		cancel()
		if isDNS(err) {
			return http2x.Tunnel{Status: http.StatusBadGateway}, nil
		}
		s.metrics.reject("target_denied")
		return http2x.Tunnel{Status: http.StatusForbidden}, nil
	}

	inner := reconstructH2Request(in)
	inner.Body = http.NoBody
	inner.ContentLength = 0
	if inner.Header == nil {
		inner.Header = make(http.Header)
	}
	inner.Header.Set("Upgrade", "websocket")
	inner.Header.Set("Connection", "Upgrade")
	if inner.Header.Get("Sec-WebSocket-Version") == "" {
		inner.Header.Set("Sec-WebSocket-Version", "13")
	}
	if inner.Header.Get("Sec-WebSocket-Key") == "" {
		inner.Header.Set("Sec-WebSocket-Key", randomWebSocketKey())
	}
	inner = withH2Meta(inner, h2Meta{
		streamID: in.ID,
		protocol: model.FlowProtocolWebSocket,
		pseudos:  append([]model.Header(nil), in.Pseudos...),
	})
	out, cap := s.originRequest(dialCtx, inner, res, host, port, nil, sess)
	out.Method = http.MethodGet
	out.Proto = "HTTP/1.1"
	out.ProtoMajor = 1
	out.ProtoMinor = 1
	out.Body = nil
	out.ContentLength = 0
	stripLeadingColonHeaders(out.Header)
	resp, sticky, err := s.roundTripUpgrade(dialCtx, out, res, sess)
	cancel()
	if err != nil {
		return http2x.Tunnel{Status: http.StatusBadGateway}, nil
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = drainOriginBody(resp)
		if sticky != nil {
			_ = sticky.Close()
		}
		return http2x.Tunnel{Status: resp.StatusCode, Headers: tunnelResponseHeaders(resp.Header)}, nil
	}
	s.track(sticky)
	inspect := s.specOf(sess).Protocols.WebSocket.InspectFrames
	f := s.flowFromReq(inner, host, "http", http.StatusOK, "", started)
	f.Protocol = model.FlowProtocolWebSocket
	f.Status = http.StatusOK
	f.HTTP2 = &model.HTTP2Info{StreamID: in.ID}
	if cap != nil {
		f.Request.Body = cap.buf
		f.Request.Truncated = cap.truncated
	}
	s.metrics.session("ok")
	origin := wrapOriginUpgrade(sticky, resp.Body)
	return http2x.Tunnel{
		Kind:    http2x.TunnelWebSocket,
		Headers: tunnelResponseHeaders(resp.Header),
		AfterAck: func(client net.Conn) {
			defer s.untrack(sticky)
			defer func() { _ = sticky.Close() }()
			defer func() {
				if resp != nil && resp.Body != nil {
					_ = resp.Body.Close()
				}
			}()
			if client == nil {
				return
			}
			defer func() { _ = client.Close() }()
			if inspect {
				s.inspectUpgrade(client, nil, origin, origin, host, inner, sess, f)
				s.capture(f, sess)
				return
			}
			s.capture(f, sess)
			s.tunnelUpgrade(client, nil, origin, origin, s.specOf(sess).Proxy.Admission)
		},
	}, nil
}

func h2cConnectRequest(in http2x.Stream) *http.Request {
	hdr := make(http.Header, len(in.Headers))
	for _, h := range in.Headers {
		if h.Name == "" {
			continue
		}
		hdr.Add(h.Name, h.Value)
	}
	return &http.Request{
		Method:     http.MethodConnect,
		Host:       in.Authority,
		URL:        &url.URL{Host: in.Authority},
		Header:     hdr,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
	}
}

func h2cConnectFlow(req *http.Request, host string, streamID uint32, status int, ferr string, started time.Time) *model.Flow {
	f := connectFlow(req, host, status, ferr, started)
	if streamID != 0 {
		f.HTTP2 = &model.HTTP2Info{StreamID: streamID}
	}
	return f
}

func h2cForbidden(in http2x.Stream) bool {
	for _, h := range in.Pseudos {
		if strings.EqualFold(h.Name, ":protocol") {
			return true
		}
	}
	hdr := make(http.Header, len(in.Headers))
	for _, h := range in.Headers {
		hdr.Add(h.Name, h.Value)
	}
	return httputilx.IsWebSocketUpgrade(hdr)
}

type captureRW struct {
	h           http.Header
	code        int
	body        bytes.Buffer
	wroteHeader bool
}

func newCaptureRW() *captureRW {
	return &captureRW{h: make(http.Header)}
}

func (c *captureRW) Header() http.Header {
	if c.h == nil {
		c.h = make(http.Header)
	}
	return c.h
}

func (c *captureRW) WriteHeader(code int) {
	if c == nil || c.wroteHeader {
		return
	}
	c.wroteHeader = true
	c.code = code
}

func (c *captureRW) Write(p []byte) (int, error) {
	if c == nil {
		return 0, io.ErrClosedPipe
	}
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	return c.body.Write(p)
}

func (c *captureRW) response() *http.Response {
	if c == nil {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Proto:      "HTTP/2.0",
			ProtoMajor: 2,
		}
	}
	code := c.code
	if !c.wroteHeader {
		code = http.StatusInternalServerError
	}
	body := c.body.Bytes()
	var r io.ReadCloser = http.NoBody
	if len(body) > 0 {
		r = io.NopCloser(bytes.NewReader(body))
	}
	return &http.Response{
		StatusCode:    code,
		Header:        c.Header(),
		Body:          r,
		ContentLength: int64(len(body)),
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
	}
}

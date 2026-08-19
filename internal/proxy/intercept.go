package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/httputilx"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/rules"
	"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm"
)

// interceptMeta is shared intercept input after the client is already acked.
type interceptMeta struct {
	ConnectHost  string
	Port         string
	Res          resolved
	Started      time.Time
	ClientReq    *http.Request
	Via          string
	OriginalDest string
	SOCKS        *model.SOCKSInfo
}

// serveInterceptConn runs dual handshake + inner HTTP. It must not write
// HTTP 200; CONNECT already did.
func (s *Server) serveInterceptConn(client net.Conn, bufrw *bufio.ReadWriter, up net.Conn, meta interceptMeta, sess *ruleSession) {
	req := meta.ClientReq
	host := meta.ConnectHost
	port := meta.Port
	res := meta.Res
	started := meta.Started
	if sess == nil {
		sess = s.beginSession()
	}
	auth := sess.auth
	if auth == nil {
		auth = s.auth
	}
	if auth == nil {
		s.failIntercept(req, host, started, tlsmitm.ResultMintFail, sess)
		return
	}
	rawClient := wrapHijacked(client, bufrw)
	hsTO := sess.spec.Proxy.Admission.HeaderTimeout
	if hsTO <= 0 {
		hsTO = defaultHeaderTimeout
	}
	hsCtx, cancel := context.WithTimeout(s.ctx, hsTO)
	defer cancel()
	_ = client.SetDeadline(time.Now().Add(hsTO))

	clientTLS, err := auth.HandshakeServer(hsCtx, rawClient, host, handshakeClientNextProtos(sess.spec))
	if err != nil {
		s.failIntercept(req, host, started, tlsmitm.ResultTLSHandshake, sess)
		return
	}

	sni := clientTLS.ConnectionState().ServerName
	if sni != "" && !strings.EqualFold(sni, host) && !hostNameAllowed(sess.spec.Proxy.Targets, sni) {
		s.metrics.reject("target_denied")
		s.capture(connectErrFlow(req, host, model.FlowStateError, string(domainerr.CodeTargetDenied), started), sess)
		return
	}
	upName := sni
	if upName == "" {
		upName = host
	}

	_ = up.SetDeadline(time.Now().Add(hsTO))
	upTLS, err := auth.HandshakeClient(hsCtx, up, upName, handshakeOriginNextProtos(sess.spec, clientTLS.ConnectionState().NegotiatedProtocol))
	if err != nil {
		result := tlsmitm.ResultUpstreamTLS
		if tlsmitm.IsVerifyError(err) {
			result = tlsmitm.ResultUpstreamVerifyFail
		}
		s.failIntercept(req, host, started, result, sess)
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})
	s.setSessionDeadline(sess.spec.Proxy.Admission, clientTLS, upTLS)

	s.metrics.tlsIntercept(tlsmitm.ResultOK)
	s.innerHTTP(clientTLS, upTLS, req, host, port, res, started, auth, sni, sess)
}

func (s *Server) failIntercept(req *http.Request, host string, started time.Time, result string, sess *ruleSession) {
	s.metrics.tlsIntercept(result)
	s.capture(connectErrFlow(req, host, model.FlowStateError, result, started), sess)
}

func connectErrFlow(req *http.Request, host, state, ferr string, started time.Time) *model.Flow {
	f := connectFlow(req, host, 0, ferr, started)
	f.State = state
	f.Scheme = "https"
	f.Intercepted = false
	return f
}

func hostNameAllowed(t model.TargetsSpec, host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if matchHostList(t.DenyHosts, host) {
		return false
	}
	if len(t.AllowHosts) > 0 && !matchHostList(t.AllowHosts, host) {
		return false
	}
	return true
}

type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func wrapHijacked(c net.Conn, bufrw *bufio.ReadWriter) net.Conn {
	if bufrw == nil {
		return c
	}
	return &readerConn{Conn: c, r: bufrw}
}

func (s *Server) innerHTTP(clientTLS, upTLS *tls.Conn, creq *http.Request, host, port string, res resolved, started time.Time, auth *tlsmitm.Authority, sni string, sess *ruleSession) {
	info := s.tlsInfo(clientTLS, upTLS, auth, sni, host)
	var (
		mu    sync.Mutex
		given bool
	)
	proto := http1Only()
	ad := s.specOf(sess).Proxy.Admission
	sessionEnd := time.Time{}
	if ad.SessionTimeout > 0 {
		sessionEnd = started.Add(ad.SessionTimeout)
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		Protocols:             proto,
		MaxIdleConns:          1,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       ad.IdleTimeout,
		ResponseHeaderTimeout: ad.UpstreamTimeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			defer mu.Unlock()
			if given {
				return nil, errors.New("proxy: intercepted CONNECT refuses redial")
			}
			given = true
			return upTLS, nil
		},
	}
	defer tr.CloseIdleConnections()

	br := bufio.NewReader(clientTLS)
	for {
		idle := ad.IdleTimeout
		if idle <= 0 {
			idle = defaultIdleTimeout
		}
		dl := time.Now().Add(idle)
		if !sessionEnd.IsZero() && dl.After(sessionEnd) {
			dl = sessionEnd
		}
		_ = clientTLS.SetReadDeadline(dl)
		inner, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if inner.Method == "PRI" {
			s.metrics.tlsIntercept(tlsmitm.ResultHTTP2Inner)
			s.capture(connectErrFlow(creq, host, model.FlowStateError, tlsmitm.ResultHTTP2Inner, time.Now()), sess)
			return
		}
		if s.roundTripInner(tr, clientTLS, upTLS, br, inner, host, port, res, info, sess) {
			return
		}
	}
}

func (s *Server) tlsInfo(clientTLS, upTLS *tls.Conn, auth *tlsmitm.Authority, sni, connectHost string) *model.TLSInfo {
	st := clientTLS.ConnectionState()
	if sni == "" {
		sni = st.ServerName
	}
	up := upTLS.ConnectionState()
	verified := len(up.VerifiedChains) > 0
	if auth != nil && auth.InsecureSkipVerify() {
		verified = false
	}
	name := sni
	if name == "" {
		name = connectHost
	}
	var leafDNS []string
	if auth != nil {
		leafDNS = auth.LeafDNS(name)
	}
	return &model.TLSInfo{
		SNI:              sni,
		Version:          tls.VersionName(st.Version),
		CipherSuite:      tls.CipherSuiteName(st.CipherSuite),
		ALPN:             st.NegotiatedProtocol,
		UpstreamVerified: verified,
		LeafDNS:          leafDNS,
	}
}

func (s *Server) roundTripInner(tr *http.Transport, clientTLS, upTLS *tls.Conn, br *bufio.Reader, inner *http.Request, host, port string, res resolved, info *model.TLSInfo, pinned *ruleSession) (stop bool) {
	started := time.Now()
	sess := pinned.fork()
	sess.reqHit = s.matchHit(sess, model.RulePhaseRequest, host, inner, inner.Header, true)
	if handled := s.runRequestRulesWrite(s.ctx, inner, host, "https", started, sess, func(resp *http.Response) {
		_ = writeConnResponse(clientTLS, resp)
	}); handled {
		return false
	}

	upCtx, upCancel := s.upstreamCtxSess(s.ctx, sess)
	defer upCancel()
	out, cap := s.innerOriginRequest(upCtx, inner, res, host, port, sess.reqCap, sess)
	if cap != nil {
		sess.reqCap = cap
	}
	resp, err := tr.RoundTrip(out)
	if err != nil {
		drainBody(inner)
		f := s.innerFlow(inner, host, port, http.StatusBadGateway, "upstream", started, info, sess.reqCap, nil)
		s.captureRule(f, inner, sess.reqCap, nil, nil, sess, sess.reqHit)
		writeHijackedError(clientTLS, http.StatusBadGateway, domainerr.CodeInternalError, "upstream request failed")
		_ = clientTLS.Close()
		_ = upTLS.Close()
		return true
	}
	defer func() { _ = resp.Body.Close() }()

	ws := httputilx.IsWebSocketUpgrade(inner.Header) && resp.StatusCode == http.StatusSwitchingProtocols
	httputilx.PrepareResponse(resp.Header, ws)
	if ws {
		if hit := s.matchHit(sess, model.RulePhaseResponse, host, inner, resp.Header, false); hit != nil {
			s.metrics.ruleHit(rules.ActionLateSkip)
		}
		if br != nil && br.Buffered() > 0 {
			n := br.Buffered()
			b, _ := br.Peek(n)
			_, _ = upTLS.Write(b)
			_, _ = br.Discard(n)
		}
		if err := writeSwitching(clientTLS, resp); err != nil {
			s.capture(s.innerFlow(inner, host, port, resp.StatusCode, "client", started, info, sess.reqCap, nil), sess)
			return true
		}
		f := s.innerFlow(inner, host, port, http.StatusSwitchingProtocols, "", started, info, sess.reqCap, nil)
		f.Protocol = model.FlowProtocolWebSocket
		s.capture(f, sess)
		s.metrics.session("ok")
		s.tunnelUpgrade(clientTLS, nil, upTLS, resp.Body, s.specOf(sess).Proxy.Admission)
		return true
	}

	s.finishConnResponse(s.ctx, clientTLS, inner, resp, host, port, "https", started, sess, info)
	return false
}

// handshakeClientNextProtos is ALPN advertised to the inner client (D46).
// Flag off stays http/1.1 so 1.0 goldens are unchanged.
func handshakeClientNextProtos(spec model.Spec) []string {
	if spec.Protocols.HTTP2.Enabled {
		return []string{"h2", tlsmitm.ALPN}
	}
	return []string{tlsmitm.ALPN}
}

// handshakeOriginNextProtos prefers the client-negotiated proto, then the other (D32).
func handshakeOriginNextProtos(spec model.Spec, negotiated string) []string {
	if !spec.Protocols.HTTP2.Enabled {
		return []string{tlsmitm.ALPN}
	}
	switch negotiated {
	case "h2":
		return []string{"h2", tlsmitm.ALPN}
	case tlsmitm.ALPN:
		return []string{tlsmitm.ALPN, "h2"}
	default:
		return []string{"h2", tlsmitm.ALPN}
	}
}

func drainBody(req *http.Request) {
	if req == nil || req.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, req.Body)
	_ = req.Body.Close()
}

func (s *Server) innerOriginRequest(ctx context.Context, req *http.Request, res resolved, host, port string, preCap *cappedWriter, sess *ruleSession) (*http.Request, *cappedWriter) {
	out := req.Clone(ctx)
	out.RequestURI = ""
	// Scheme http: the one-shot DialContext already returns a handshaked tls.Conn.
	out.URL = &url.URL{
		Scheme:   "http",
		Host:     pinnedAddr(res.Selected, res.Port),
		Path:     req.URL.Path,
		RawPath:  req.URL.RawPath,
		RawQuery: req.URL.RawQuery,
	}
	if out.URL.Path == "" {
		out.URL.Path = "/"
	}
	out.Host = httpsOriginHost(host, port)
	if req.Host != "" {
		out.Host = req.Host
	}
	httputilx.PrepareRequest(out.Header)
	if preCap != nil {
		return out, preCap
	}
	max := s.maxBodyOf(sess)
	var capw *cappedWriter
	if out.Body != nil {
		var teed io.ReadCloser
		teed, capw = teeBody(out.Body, max)
		out.Body = teed
	}
	return out, capw
}

func httpsOriginHost(host, port string) string {
	if port != "" && port != "443" {
		return net.JoinHostPort(host, port)
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

func (s *Server) innerFlow(req *http.Request, host, port string, status int, ferr string, started time.Time, info *model.TLSInfo, reqCap, respCap *cappedWriter) *model.Flow {
	state := model.FlowStateCompleted
	if ferr != "" {
		state = model.FlowStateError
	}
	u := ""
	if req != nil && req.URL != nil {
		u = (&url.URL{
			Scheme:   "https",
			Host:     httpsOriginHost(host, port),
			Path:     req.URL.Path,
			RawQuery: req.URL.RawQuery,
		}).String()
	}
	method := ""
	if req != nil {
		method = req.Method
	}
	f := &model.Flow{
		StartedAt:   started.UTC(),
		CompletedAt: time.Now().UTC(),
		State:       state,
		Method:      method,
		URL:         u,
		Host:        host,
		Scheme:      "https",
		Protocol:    model.FlowProtocolHTTP11,
		Status:      status,
		Error:       ferr,
		Intercepted: true,
		TLS:         info,
	}
	if req != nil {
		f.Request.Headers = headersFrom(req.Header)
	}
	if reqCap != nil {
		f.Request.Body = reqCap.buf
		f.Request.Size = len(reqCap.buf)
		f.Request.Truncated = reqCap.truncated
		f.Truncated = f.Truncated || reqCap.truncated
	}
	if respCap != nil {
		f.Response.Body = respCap.buf
		f.Response.Size = len(respCap.buf)
		f.Response.Truncated = respCap.truncated
		f.Truncated = f.Truncated || respCap.truncated
	}
	return f
}

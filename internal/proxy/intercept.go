package proxy

import (
	"bufio"
	"bytes"
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
	"github.com/hilather/go-lab-mitmproxy/internal/http2x"
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
	upTLS, err := auth.HandshakeClient(hsCtx, up, upName, handshakeOriginNextProtos())
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
		mu       sync.Mutex
		originMu sync.Mutex
		given    bool
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
		MaxConnsPerHost:       1, // D44: missed unlock must queue, not redial
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

	if clientTLS.ConnectionState().NegotiatedProtocol == http2x.NextProtoH2 && s.specOf(sess).Protocols.HTTP2.Enabled {
		_ = http2x.ServeClient(s.ctx, clientTLS, func(ctx context.Context, in http2x.Stream) (*http.Response, []model.Header, error) {
			return s.roundTripInnerH2(ctx, tr, &originMu, upTLS, in, host, port, res, info, sess)
		})
		return
	}

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

// handshakeOriginNextProtos is origin ALPN. Inner h2 is transcoded onto
// HTTP/1.1 origin until origin transcode; this stays http/1.1 even when
// the leaf advertises h2.
func handshakeOriginNextProtos() []string {
	return []string{tlsmitm.ALPN}
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
		Protocol:    requestProtocol(req),
		Status:      status,
		Error:       ferr,
		Intercepted: true,
		TLS:         info,
	}
	applyH2Meta(f, req)
	if req != nil {
		f.Request.Headers = requestCaptureHeaders(req)
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

type h2MetaKey struct{}

type h2Meta struct {
	streamID uint32
	protocol string
	pseudos  []model.Header
}

func withH2Meta(req *http.Request, meta h2Meta) *http.Request {
	if req == nil {
		return nil
	}
	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return req.WithContext(context.WithValue(ctx, h2MetaKey{}, meta))
}

func h2MetaFrom(req *http.Request) (h2Meta, bool) {
	if req == nil {
		return h2Meta{}, false
	}
	meta, ok := req.Context().Value(h2MetaKey{}).(h2Meta)
	return meta, ok
}

func requestProtocol(req *http.Request) string {
	if meta, ok := h2MetaFrom(req); ok && meta.protocol != "" {
		return meta.protocol
	}
	if req != nil && req.ProtoMajor == 2 {
		return model.FlowProtocolHTTP2
	}
	return model.FlowProtocolHTTP11
}

func applyH2Meta(f *model.Flow, req *http.Request) {
	if f == nil {
		return
	}
	meta, ok := h2MetaFrom(req)
	if !ok {
		return
	}
	if meta.protocol != "" {
		f.Protocol = meta.protocol
	}
	if meta.streamID != 0 {
		f.HTTP2 = &model.HTTP2Info{StreamID: meta.streamID}
	}
}

func requestCaptureHeaders(req *http.Request) []model.Header {
	if req == nil {
		return nil
	}
	if meta, ok := h2MetaFrom(req); ok && len(meta.pseudos) > 0 {
		return mergePseudoHeaders(meta.pseudos, req.Header)
	}
	return headersFrom(req.Header)
}

func mergePseudoHeaders(pseudos []model.Header, hdr http.Header) []model.Header {
	out := append([]model.Header(nil), pseudos...)
	seen := make(map[string]bool, len(pseudos))
	for _, p := range pseudos {
		seen[strings.ToLower(p.Name)] = true
	}
	for _, h := range headersFrom(hdr) {
		if seen[strings.ToLower(h.Name)] {
			continue
		}
		out = append(out, h)
	}
	return out
}

func h2InnerForbidden(in http2x.Stream) bool {
	if strings.EqualFold(in.Method, http.MethodConnect) {
		return true
	}
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

func reconstructH2Request(in http2x.Stream) *http.Request {
	rawPath := in.Path
	if rawPath == "" {
		rawPath = "/"
	}
	u, err := url.ParseRequestURI(rawPath)
	if err != nil {
		u = &url.URL{Path: rawPath}
	}
	hdr := make(http.Header, len(in.Pseudos)+len(in.Headers))
	for _, h := range in.Pseudos {
		if h.Name == "" {
			continue
		}
		hdr.Add(h.Name, h.Value)
	}
	for _, h := range in.Headers {
		if h.Name == "" {
			continue
		}
		hdr.Add(h.Name, h.Value)
	}
	host := in.Authority
	if host == "" {
		host = hdr.Get(":authority")
	}
	req := &http.Request{
		Method:     in.Method,
		URL:        u,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header:     hdr,
		Body:       in.Body,
		Host:       host,
		RequestURI: rawPath,
	}
	if req.Method == "" {
		req.Method = http.MethodGet
	}
	return withH2Meta(req, h2Meta{
		streamID: in.ID,
		protocol: model.FlowProtocolHTTP2,
		pseudos:  append([]model.Header(nil), in.Pseudos...),
	})
}

func stripLeadingColonHeaders(h http.Header) {
	if h == nil {
		return
	}
	for k := range h {
		if strings.HasPrefix(k, ":") {
			delete(h, k)
		}
	}
}

func drainOriginBody(resp *http.Response) []model.Header {
	if resp == nil || resp.Body == nil {
		return nil
	}
	full, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	trailers := headersFrom(resp.Trailer)
	resp.Body = io.NopCloser(bytes.NewReader(full))
	resp.ContentLength = int64(len(full))
	resp.TransferEncoding = nil
	return trailers
}

func rewindResponseBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
}

func badGatewayH2() *http.Response {
	return &http.Response{
		Status:        "502 Bad Gateway",
		StatusCode:    http.StatusBadGateway,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		Header:        make(http.Header),
		Body:          http.NoBody,
		ContentLength: 0,
	}
}

// roundTripInnerH2 runs match/capture/origin for one h2 stream (D53).
// It never writes HTTP/1.1 to the client TLS conn and never closes CONNECT.
func (s *Server) roundTripInnerH2(ctx context.Context, tr *http.Transport, originMu *sync.Mutex, upTLS *tls.Conn, in http2x.Stream, host, port string, res resolved, info *model.TLSInfo, pinned *ruleSession) (*http.Response, []model.Header, error) {
	if h2InnerForbidden(in) {
		s.metrics.reject("http2")
		return nil, nil, http2x.ErrInnerCONNECT
	}
	started := time.Now()
	sess := pinned.fork()
	inner := reconstructH2Request(in)
	sess.reqHit = s.matchHit(sess, model.RulePhaseRequest, host, inner, inner.Header, true)

	var syn *http.Response
	handled := s.runRequestRulesWrite(ctx, inner, host, "https", started, sess, func(resp *http.Response) {
		syn = resp
	})
	if handled {
		if syn == nil {
			return badGatewayH2(), nil, nil
		}
		rewindResponseBody(syn)
		return syn, nil, nil
	}

	if originMu == nil {
		originMu = &sync.Mutex{}
	}
	var (
		resp     *http.Response
		trailers []model.Header
		err      error
	)
	func() {
		originMu.Lock()
		defer originMu.Unlock()
		upCtx, upCancel := s.upstreamCtxSess(ctx, sess)
		defer upCancel()
		out, cap := s.innerOriginRequest(upCtx, inner, res, host, port, sess.reqCap, sess)
		if cap != nil {
			sess.reqCap = cap
		}
		stripLeadingColonHeaders(out.Header)
		resp, err = tr.RoundTrip(out)
		if err != nil {
			drainBody(inner)
			if upTLS != nil {
				_ = upTLS.Close()
			}
			return
		}
		trailers = drainOriginBody(resp)
	}()
	if err != nil {
		f := s.innerFlow(inner, host, port, http.StatusBadGateway, "upstream", started, info, sess.reqCap, nil)
		s.captureRule(f, inner, sess.reqCap, nil, nil, sess, sess.reqHit)
		return badGatewayH2(), nil, nil
	}
	sess.respTrailers = trailers

	var outResp *http.Response
	s.finishResponseWrite(ctx, inner, resp, host, port, "https", started, sess, info, func(r *http.Response) error {
		rewindResponseBody(r)
		outResp = r
		return nil
	})
	if outResp == nil {
		rewindResponseBody(resp)
		outResp = resp
	}
	return outResp, trailers, nil
}

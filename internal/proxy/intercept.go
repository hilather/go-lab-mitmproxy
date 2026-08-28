package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
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
	innerALPN := clientTLS.ConnectionState().NegotiatedProtocol
	upTLS, err := auth.HandshakeClient(hsCtx, up, upName, handshakeOriginNextProtos(sess.spec, innerALPN))
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
		originRT := http.RoundTripper(tr)
		originH2 := upTLS.ConnectionState().NegotiatedProtocol == http2x.NextProtoH2
		var serialize *sync.Mutex
		if originH2 {
			spec := s.specOf(sess)
			h2tr, err := http2x.NewOriginConn(upTLS, http2x.OriginOpts{
				CapturePush: spec.Protocols.HTTP2.CapturePush,
				MaxBody:     int(s.maxBodyOf(sess)),
				OnPush:      s.onOriginPush(host, port, info, sess),
				OnRST:       func() { s.metrics.h2PushCaptured("rst") },
			})
			if err != nil {
				s.failIntercept(creq, host, started, tlsmitm.ResultUpstreamTLS, sess)
				_ = clientTLS.Close()
				_ = upTLS.Close()
				return
			}
			originRT = h2tr
		} else {
			serialize = &originMu
		}
		h := func(ctx context.Context, in http2x.Stream) (*http.Response, []model.Header, error) {
			return s.roundTripInnerH2(ctx, originRT, serialize, upTLS, in, host, port, res, info, sess, originH2)
		}
		spec := s.specOf(sess)
		if spec.Protocols.HTTP2.ExtendedConnect {
			_ = http2x.ServeConn(s.ctx, clientTLS, nil, http2x.ServeOpts{
				Preface:               http2x.PrefaceFull,
				EnableConnectProtocol: true,
				MaxConcurrentStreams:  uint32(spec.Proxy.Admission.MaxConcurrentStreams),
			}, h, func(ctx context.Context, in http2x.Stream) (http2x.Tunnel, error) {
				return s.innerH2Tunnel(ctx, originRT, serialize, upTLS, in, host, port, res, info, sess, originH2)
			})
			return
		}
		_ = http2x.ServeClient(s.ctx, clientTLS, h)
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
	if httputilx.IsWebSocketUpgrade(inner.Header) && !sess.spec.Protocols.WebSocket.Enabled {
		s.metrics.reject("websocket")
		f := s.innerFlow(inner, host, port, http.StatusForbidden, string(domainerr.CodeForbidden), started, info, sess.reqCap, nil)
		f.Protocol = model.FlowProtocolWebSocket
		s.capture(f, sess)
		if err := writeConnResponse(clientTLS, innerForbiddenResponse("websocket is disabled", "spec.protocols.websocket.enabled")); err != nil {
			_ = clientTLS.Close()
			_ = upTLS.Close()
			return true
		}
		return false
	}
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
		leftover := takeBuffered(br)
		inspect := s.specOf(sess).Protocols.WebSocket.InspectFrames
		if !inspect && len(leftover) > 0 {
			_, _ = upTLS.Write(leftover)
			leftover = nil
		}
		if err := writeSwitching(clientTLS, resp); err != nil {
			s.capture(s.innerFlow(inner, host, port, resp.StatusCode, "client", started, info, sess.reqCap, nil), sess)
			return true
		}
		f := s.innerFlow(inner, host, port, http.StatusSwitchingProtocols, "", started, info, sess.reqCap, nil)
		f.Protocol = model.FlowProtocolWebSocket
		s.metrics.session("ok")
		if inspect {
			s.inspectUpgrade(clientTLS, leftover, upTLS, resp.Body, sess, f)
			s.capture(f, sess)
			return true
		}
		s.capture(f, sess)
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

// handshakeOriginNextProtos is origin ALPN from the session snapshot (D46)
// and the inner negotiated ALPN. Origin h2 is offered only when both
// protocols.http2.origin and the inner leaf negotiated h2 (D64). Inner
// http/1.1 never offers origin h2. Flag-off keeps D32/D44 transcode.
func handshakeOriginNextProtos(spec model.Spec, innerALPN string) []string {
	if spec.Protocols.HTTP2.Origin && innerALPN == http2x.NextProtoH2 {
		return []string{http2x.NextProtoH2, tlsmitm.ALPN}
	}
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

func (s *Server) onOriginPush(host, port string, info *model.TLSInfo, pinned *ruleSession) func(http2x.Pushed) {
	return func(p http2x.Pushed) {
		sess := pinned.fork()
		started := time.Now()
		rawPath := p.Path
		if rawPath == "" {
			rawPath = "/"
		}
		u := &url.URL{Scheme: "https", Host: httpsOriginHost(host, port)}
		if parsed, err := url.ParseRequestURI(rawPath); err == nil {
			u.Path = parsed.Path
			u.RawQuery = parsed.RawQuery
		} else {
			u.Path = rawPath
		}
		f := &model.Flow{
			StartedAt:   started.UTC(),
			CompletedAt: time.Now().UTC(),
			State:       model.FlowStateCompleted,
			Method:      p.Method,
			URL:         u.String(),
			Host:        host,
			Scheme:      "https",
			Protocol:    model.FlowProtocolHTTP2,
			Status:      p.Status,
			Intercepted: true,
			TLS:         info,
			HTTP2: &model.HTTP2Info{
				StreamID:       p.PromisedID,
				ParentStreamID: p.ParentStreamID,
				PromisedID:     p.PromisedID,
				Pushed:         true,
			},
			Request: model.HTTPMessage{Headers: p.RequestHeaders},
			Response: model.HTTPMessage{
				Headers:   p.ResponseHeaders,
				Body:      p.ResponseBody,
				Size:      len(p.ResponseBody),
				Truncated: p.ResponseTruncated,
			},
			Truncated: p.ResponseTruncated,
		}
		s.metrics.h2PushCaptured("ok")
		s.capture(f, sess)
	}
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
		if isPseudoHeaderName(k) {
			delete(h, k)
		}
	}
}

func isPseudoHeaderName(name string) bool {
	return strings.HasPrefix(name, ":")
}

func headerValue(headers []model.Header, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// dropH2RequestTrailers strips request trailers before an HTTP/1.1 origin
// (D44). Capture keeps values on the flow; the origin hop never sees them.
func (s *Server) dropH2RequestTrailers(inner *http.Request, in http2x.Stream) []model.Header {
	var trailers []model.Header
	if len(in.Trailers) > 0 {
		trailers = append(trailers, in.Trailers...)
	}
	dropped := len(trailers) > 0
	if inner != nil {
		if inner.Header != nil && inner.Header.Get("Trailer") != "" {
			dropped = true
		}
		if len(inner.Trailer) > 0 {
			dropped = true
			trailers = append(trailers, headersFrom(inner.Trailer)...)
			// Clone would otherwise send HTTP/1.1 trailers on RoundTrip.
			inner.Trailer = nil
		}
	}
	if dropped {
		s.metrics.h2TrailerDropped()
	}
	return trailers
}

func drainOriginBody(resp *http.Response) []model.Header {
	if resp == nil || resp.Body == nil {
		return nil
	}
	// D44: fully read+close so the origin conn is idle before unlock.
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
// originH2 multiplexes on the already-dialed origin TCP (D64); D44 mutex
// is only used when origin is HTTP/1.1.
func (s *Server) roundTripInnerH2(ctx context.Context, rt http.RoundTripper, originMu *sync.Mutex, upTLS *tls.Conn, in http2x.Stream, host, port string, res resolved, info *model.TLSInfo, pinned *ruleSession, originH2 bool) (*http.Response, []model.Header, error) {
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

	if !originH2 {
		sess.reqTrailers = s.dropH2RequestTrailers(inner, in)
	} else if len(in.Trailers) > 0 {
		sess.reqTrailers = append([]model.Header(nil), in.Trailers...)
	}

	var (
		resp     *http.Response
		trailers []model.Header
		err      error
	)
	func() {
		// D44: mutex covers RoundTrip and the full origin body drain so a
		// second stream cannot Dial while resp.Body still owns the conn.
		// Origin h2 multiplexes on one TCP; do not hold this lock (D64).
		if originMu != nil {
			originMu.Lock()
			defer originMu.Unlock()
		}
		upCtx, upCancel := s.upstreamCtxSess(ctx, sess)
		defer upCancel()
		out, cap := s.innerOriginRequest(upCtx, inner, res, host, port, sess.reqCap, sess)
		if cap != nil {
			sess.reqCap = cap
		}
		stripLeadingColonHeaders(out.Header)
		if originH2 && out.URL != nil {
			out.URL.Scheme = "https"
		}
		resp, err = rt.RoundTrip(out)
		if err != nil {
			drainBody(inner)
			// D44 h1 origin owns the one TCP. Origin h2 multiplexes;
			// a stream error must not Close the shared CONNECT (D64).
			if !originH2 && upTLS != nil {
				_ = upTLS.Close()
			}
			return
		}
		trailers = drainOriginBody(resp)
		httputilx.PrepareResponse(resp.Header, false)
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

func randomWebSocketKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "dGhlIHNhbXBsZSBub25jZQ=="
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

// innerH2Tunnel handles inner CONNECT / :protocol when extendedConnect is on.
// Nested CONNECT without :protocol and other :protocol values RST with no flow
// (D48 remainder). :protocol=websocket transcodes to origin HTTP/1.1 Upgrade
// when origin is h1, or RFC 8441 Extended CONNECT when origin negotiated h2.
func (s *Server) innerH2Tunnel(ctx context.Context, rt http.RoundTripper, originMu *sync.Mutex, upTLS *tls.Conn, in http2x.Stream, host, port string, res resolved, info *model.TLSInfo, pinned *ruleSession, originH2 bool) (http2x.Tunnel, error) {
	proto := strings.TrimSpace(in.Protocol)
	if proto == "" || !strings.EqualFold(in.Method, http.MethodConnect) || !strings.EqualFold(proto, "websocket") {
		s.metrics.reject("http2")
		return http2x.Tunnel{}, http2x.ErrInnerCONNECT
	}
	started := time.Now()
	sess := pinned.fork()
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
	sess.reqHit = s.matchHit(sess, model.RulePhaseRequest, host, inner, inner.Header, true)
	var syn *http.Response
	handled := s.runRequestRulesWrite(ctx, inner, host, "https", started, sess, func(resp *http.Response) {
		syn = resp
	})
	if handled {
		status := http.StatusForbidden
		var hdrs []model.Header
		if syn != nil {
			if syn.StatusCode != 0 {
				status = syn.StatusCode
			}
			hdrs = headersFrom(syn.Header)
		}
		return http2x.Tunnel{Status: status, Headers: hdrs}, nil
	}

	unlock := func() {}
	if originMu != nil {
		originMu.Lock()
		unlock = sync.OnceFunc(originMu.Unlock)
	}

	parent := ctx
	if parent == nil {
		parent = context.Background()
		if s.ctx != nil {
			parent = s.ctx
		}
	}
	var (
		upCtx    context.Context
		upCancel context.CancelFunc
	)
	if originH2 {
		// Do not put UpstreamTimeout on the long-lived CONNECT stream:
		// http2.Transport RSTs on ctx cancel, which would tear down
		// websocket AfterAck (D64). Bound only the handshake wait.
		upCtx, upCancel = context.WithCancel(parent)
	} else {
		upCtx, upCancel = s.upstreamCtxSess(parent, sess)
	}
	release := upCancel
	defer func() {
		if release != nil {
			release()
		}
	}()
	out, cap := s.innerOriginRequest(upCtx, inner, res, host, port, sess.reqCap, sess)
	if cap != nil {
		sess.reqCap = cap
	}
	stripLeadingColonHeaders(out.Header)
	var pw *io.PipeWriter
	if originH2 {
		if out.URL != nil {
			out.URL.Scheme = "https"
		}
		out.Method = http.MethodConnect
		out.Proto = "HTTP/2.0"
		out.ProtoMajor = 2
		out.ProtoMinor = 0
		out.Header.Del("Upgrade")
		out.Header.Del("Connection")
		out.Header.Set(":protocol", "websocket")
		pr, w := io.Pipe()
		pw = w
		out.Body = pr
		out.ContentLength = -1
		out.TransferEncoding = nil
	} else {
		out.Method = http.MethodGet
		out.Proto = "HTTP/1.1"
		out.ProtoMajor = 1
		out.ProtoMinor = 1
		out.Body = nil
		out.ContentLength = 0
		out.TransferEncoding = nil
		if out.Header.Get("Sec-WebSocket-Key") == "" {
			out.Header.Set("Sec-WebSocket-Key", randomWebSocketKey())
		}
	}
	var markHeaders func()
	if originH2 {
		to := s.specOf(sess).Proxy.Admission.UpstreamTimeout
		if to <= 0 {
			to = defaultUpstreamTimeout
		}
		hsCtx, hsCancel := context.WithTimeout(upCtx, to)
		var mu sync.Mutex
		got := false
		context.AfterFunc(hsCtx, func() {
			mu.Lock()
			defer mu.Unlock()
			if !got && hsCtx.Err() == context.DeadlineExceeded {
				upCancel()
			}
		})
		markHeaders = func() {
			mu.Lock()
			got = true
			mu.Unlock()
			hsCancel()
		}
	}
	resp, err := rt.RoundTrip(out)
	if markHeaders != nil {
		markHeaders()
	}
	if !originH2 {
		upCancel()
		release = nil
	}
	if err != nil {
		if pw != nil {
			_ = pw.Close()
		}
		unlock()
		f := s.innerFlow(inner, host, port, http.StatusBadGateway, "upstream", started, info, sess.reqCap, nil)
		s.captureRule(f, inner, sess.reqCap, nil, nil, sess, sess.reqHit)
		return http2x.Tunnel{}, err
	}
	want := http.StatusSwitchingProtocols
	if originH2 {
		want = http.StatusOK
	}
	if resp.StatusCode != want {
		if pw != nil {
			_ = pw.Close()
		}
		_ = drainOriginBody(resp)
		unlock()
		httputilx.PrepareResponse(resp.Header, false)
		f := s.innerFlow(inner, host, port, resp.StatusCode, "", started, info, sess.reqCap, nil)
		f.Response.Headers = headersFrom(resp.Header)
		s.capture(f, sess)
		return http2x.Tunnel{Status: resp.StatusCode, Headers: tunnelResponseHeaders(resp.Header)}, nil
	}
	fromUp := resp.Body
	if hit := s.matchHit(sess, model.RulePhaseResponse, host, inner, resp.Header, false); hit != nil {
		s.metrics.ruleHit(rules.ActionLateSkip)
	}

	inspect := s.specOf(sess).Protocols.WebSocket.InspectFrames
	f := s.innerFlow(inner, host, port, http.StatusOK, "", started, info, sess.reqCap, nil)
	f.Protocol = model.FlowProtocolWebSocket
	f.Status = http.StatusOK
	s.metrics.session("ok")
	origin := wrapOriginUpgrade(upTLS, fromUp)
	if originH2 {
		origin = newH2OriginStream(fromUp, pw)
		release = nil
	}
	return http2x.Tunnel{
		Kind:    http2x.TunnelWebSocket,
		Headers: tunnelResponseHeaders(resp.Header),
		AfterAck: func(client net.Conn) {
			defer unlock()
			if originH2 {
				defer upCancel()
			}
			defer func() {
				if resp != nil && resp.Body != nil {
					_ = resp.Body.Close()
				}
			}()
			if client == nil {
				if pw != nil {
					_ = pw.Close()
				}
				return
			}
			if inspect {
				s.inspectUpgrade(client, nil, origin, origin, sess, f)
				s.capture(f, sess)
				return
			}
			s.capture(f, sess)
			s.tunnelUpgrade(client, nil, origin, origin, s.specOf(sess).Proxy.Admission)
		},
	}, nil
}

func tunnelResponseHeaders(h http.Header) []model.Header {
	if h == nil {
		return nil
	}
	cp := h.Clone()
	httputilx.PrepareResponse(cp, false)
	return headersFrom(cp)
}

type upgradeBodyConn struct {
	net.Conn
	rw io.ReadWriter
}

func wrapOriginUpgrade(up net.Conn, body io.Reader) net.Conn {
	rw, ok := body.(io.ReadWriter)
	if !ok || up == nil {
		return up
	}
	return &upgradeBodyConn{Conn: up, rw: rw}
}

func (c *upgradeBodyConn) Read(p []byte) (int, error)  { return c.rw.Read(p) }
func (c *upgradeBodyConn) Write(p []byte) (int, error) { return c.rw.Write(p) }

// h2OriginStream is one origin HTTP/2 stream as a net.Conn. Deadlines and
// Close must not touch the parent TLS conn (other streams multiplex on it).
type h2OriginStream struct {
	r io.ReadCloser
	w *io.PipeWriter
}

func newH2OriginStream(body io.ReadCloser, w *io.PipeWriter) *h2OriginStream {
	if body == nil {
		body = io.NopCloser(bytes.NewReader(nil))
	}
	return &h2OriginStream{r: body, w: w}
}

func (c *h2OriginStream) Read(p []byte) (int, error) {
	if c == nil || c.r == nil {
		return 0, io.EOF
	}
	return c.r.Read(p)
}

func (c *h2OriginStream) Write(p []byte) (int, error) {
	if c == nil || c.w == nil {
		return 0, io.ErrClosedPipe
	}
	return c.w.Write(p)
}

func (c *h2OriginStream) Close() error {
	_ = c.CloseWrite()
	if c != nil && c.r != nil {
		return c.r.Close()
	}
	return nil
}

func (c *h2OriginStream) CloseWrite() error {
	if c == nil || c.w == nil {
		return nil
	}
	return c.w.Close()
}

func (c *h2OriginStream) LocalAddr() net.Addr              { return streamAddr{} }
func (c *h2OriginStream) RemoteAddr() net.Addr             { return streamAddr{} }
func (c *h2OriginStream) SetDeadline(time.Time) error      { return nil }
func (c *h2OriginStream) SetReadDeadline(time.Time) error  { return nil }
func (c *h2OriginStream) SetWriteDeadline(time.Time) error { return nil }

type streamAddr struct{}

func (streamAddr) Network() string { return "tcp" }
func (streamAddr) String() string  { return "h2-origin-stream" }

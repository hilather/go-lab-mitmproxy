package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/httputilx"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/rules"
)

func (s *Server) serveAbsolute(w http.ResponseWriter, req *http.Request, sess *ruleSession) {
	started := time.Now()
	host, port, err := splitAuthority(req.URL.Host, "80")
	if err != nil {
		writeProxyError(w, http.StatusBadRequest, domainerr.CodeValidationFailed, "invalid authority", "")
		return
	}
	if sess == nil {
		sess = s.beginSession()
	}

	guardCtx, guardCancel := s.upstreamCtxSess(req.Context(), sess)
	res, err := resolveThenGuard(guardCtx, s.resolver, sess.spec.Proxy.Targets, host, port)
	guardCancel()
	if err != nil {
		s.rejectResolve(w, req, host, err)
		return
	}

	sess.reqHit = s.matchHit(sess, model.RulePhaseRequest, host, req, req.Header, true)

	ws := httputilx.IsWebSocketUpgrade(req.Header)
	if headerHasExpect(req.Header) && !ws {
		s.serveExpectAbsolute(w, req, res, host, port, started, sess)
		return
	}

	if handled := s.runRequestRules(req.Context(), w, req, host, "http", started, sess); handled {
		return
	}

	upCtx, upCancel := s.upstreamCtxSess(req.Context(), sess)
	defer upCancel()
	out, cap := s.originRequest(upCtx, req, res, host, port, sess.reqCap, sess)
	if cap != nil {
		sess.reqCap = cap
	}

	var (
		resp   *http.Response
		sticky net.Conn
	)
	if ws {
		resp, sticky, err = s.roundTripUpgrade(upCtx, out, res, sess)
	} else {
		resp, err = s.tr.RoundTrip(out)
	}
	if err != nil {
		f := s.flowFromReq(req, host, "http", 0, "upstream", started)
		s.captureRule(f, req, sess.reqCap, nil, nil, sess.reqHit)
		writeProxyError(w, http.StatusBadGateway, domainerr.CodeInternalError, "upstream request failed", "")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	websocket := ws && resp.StatusCode == http.StatusSwitchingProtocols
	httputilx.PrepareResponse(resp.Header, websocket)

	if websocket {
		if hit := s.matchHit(sess, model.RulePhaseResponse, host, req, resp.Header, false); hit != nil {
			s.metrics.ruleHit(rules.ActionLateSkip)
		}
		s.hijackUpgrade(w, req, resp, sticky, sess.reqCap, host, started)
		return
	}

	s.finishHTTPResponse(req.Context(), w, req, resp, host, "http", started, sess, nil)
}

func headerHasExpect(h http.Header) bool {
	for _, v := range h.Values("Expect") {
		if strings.EqualFold(strings.TrimSpace(v), "100-continue") {
			return true
		}
	}
	return false
}

// serveExpectAbsolute Hijacks before any body read so net/http cannot emit 100,
// then runs request/response rules on the hijacked conn.
func (s *Server) serveExpectAbsolute(w http.ResponseWriter, req *http.Request, res resolved, host, port string, started time.Time, sess *ruleSession) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeProxyError(w, http.StatusInternalServerError, domainerr.CodeInternalError, "hijack not supported", "")
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

	switch {
	case req.ContentLength > 0:
		req.Body = io.NopCloser(io.LimitReader(bufrw, req.ContentLength))
	case requestHasChunkedBody(req):
		req.Body = io.NopCloser(httputilx.NewChunkedReader(bufrw))
	default:
		req.Body = http.NoBody
		req.ContentLength = 0
	}

	write := func(resp *http.Response) {
		_ = writeConnResponse(client, resp)
		if bufrw != nil {
			_ = bufrw.Flush()
		}
	}
	if handled := s.runRequestRulesWrite(req.Context(), req, host, "http", started, sess, write); handled {
		return
	}

	upCtx, upCancel := s.upstreamCtxSess(req.Context(), sess)
	defer upCancel()
	out, cap := s.originRequest(upCtx, req, res, host, port, sess.reqCap, sess)
	if cap != nil {
		sess.reqCap = cap
	}
	resp, err := s.tr.RoundTrip(out)
	if err != nil {
		f := s.flowFromReq(req, host, "http", 0, "upstream", started)
		s.captureRule(f, req, sess.reqCap, nil, nil, sess.reqHit)
		writeHijackedError(client, http.StatusBadGateway, domainerr.CodeInternalError, "upstream request failed")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	s.finishResponseWrite(req.Context(), req, resp, host, "", "http", started, sess, nil, func(out *http.Response) error {
		if err := writeConnResponse(client, out); err != nil {
			return err
		}
		if bufrw != nil {
			return bufrw.Flush()
		}
		return nil
	})
}

func (s *Server) originRequest(ctx context.Context, req *http.Request, res resolved, host, port string, preCap *cappedWriter, sess *ruleSession) (*http.Request, *cappedWriter) {
	out := req.Clone(ctx)
	out.RequestURI = ""
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
	out.Host = originHost(host, port)
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

func requestHasChunkedBody(req *http.Request) bool {
	if req == nil {
		return false
	}
	for _, te := range req.TransferEncoding {
		if strings.EqualFold(te, "chunked") {
			return true
		}
	}
	return req.ContentLength < 0
}

func (s *Server) rejectResolve(w http.ResponseWriter, req *http.Request, host string, err error) {
	if err == nil {
		return
	}
	if isDNS(err) {
		s.capture(s.flowFromReq(req, host, "http", http.StatusBadGateway, "dns", time.Now()))
		writeProxyError(w, http.StatusBadGateway, domainerr.CodeInternalError, "dns lookup failed", "")
		return
	}
	s.metrics.reject("target_denied")
	s.capture(s.flowFromReq(req, host, "http", http.StatusForbidden, string(domainerr.CodeTargetDenied), time.Now()))
	writeProxyError(w, http.StatusForbidden, domainerr.CodeTargetDenied, "target denied", "")
}

func isDNS(err error) bool {
	return errors.Is(err, errDNS)
}

func (s *Server) flowFromReq(req *http.Request, host, scheme string, status int, ferr string, started time.Time) *model.Flow {
	state := model.FlowStateCompleted
	if ferr != "" {
		state = model.FlowStateError
	}
	u := ""
	if req != nil && req.URL != nil {
		u = req.URL.String()
	}
	method := ""
	if req != nil {
		method = req.Method
	}
	return &model.Flow{
		StartedAt:   started.UTC(),
		CompletedAt: time.Now().UTC(),
		State:       state,
		Method:      method,
		URL:         u,
		Host:        host,
		Scheme:      scheme,
		Protocol:    model.FlowProtocolHTTP11,
		Status:      status,
		Error:       ferr,
	}
}

func (s *Server) roundTripUpgrade(ctx context.Context, out *http.Request, res resolved, sess *ruleSession) (*http.Response, net.Conn, error) {
	var sticky net.Conn
	proto := http1Only()
	tr := &http.Transport{
		Proxy:                 nil,
		DisableCompression:    true,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		Protocols:             proto,
		ResponseHeaderTimeout: s.specOf(sess).Proxy.Admission.UpstreamTimeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := s.dialPinned(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			sticky = c
			return c, nil
		},
	}
	defer tr.CloseIdleConnections()
	_ = res
	resp, err := tr.RoundTrip(out.WithContext(ctx))
	return resp, sticky, err
}

func (s *Server) hijackUpgrade(w http.ResponseWriter, req *http.Request, resp *http.Response, upstream net.Conn, reqCap *cappedWriter, host string, started time.Time) {
	hj, ok := w.(http.Hijacker)
	if !ok || upstream == nil {
		writeProxyError(w, http.StatusInternalServerError, domainerr.CodeInternalError, "upgrade hijack failed", "")
		return
	}
	client, bufrw, err := hj.Hijack()
	if err != nil {
		writeProxyError(w, http.StatusInternalServerError, domainerr.CodeInternalError, "upgrade hijack failed", "")
		return
	}
	s.beginHijacked()
	defer s.endHijacked()
	s.track(client)
	s.track(upstream)
	defer s.untrack(client)
	defer s.untrack(upstream)
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()

	if err := writeSwitching(bufrw, resp); err != nil {
		return
	}
	f := s.flowFromReq(req, host, "http", http.StatusSwitchingProtocols, "", started)
	f.Protocol = model.FlowProtocolWebSocket
	if reqCap != nil {
		f.Request.Body = reqCap.buf
		f.Request.Truncated = reqCap.truncated
	}
	s.capture(f)
	s.metrics.session("ok")
	// Read leftover 101 payload from resp.Body (Transport buffered it).
	s.tunnelUpgrade(client, bufrw, upstream, resp.Body)
}

func (s *Server) tunnelUpgrade(client net.Conn, bufrw *bufio.ReadWriter, upstream net.Conn, fromUp io.Reader) {
	if bufrw != nil && bufrw.Reader.Buffered() > 0 {
		n := bufrw.Reader.Buffered()
		b, _ := bufrw.Peek(n)
		_, _ = upstream.Write(b)
		_, _ = bufrw.Discard(n)
	}
	if fromUp == nil {
		fromUp = upstream
	}
	s.setSessionDeadline(client, upstream)
	done := make(chan struct{}, 2)
	go func() {
		s.deadlineCopy(upstream, client)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		s.deadlineCopy(client, fromUp)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func writeSwitching(w io.Writer, resp *http.Response) error {
	if _, err := fmt.Fprintf(w, "HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		return err
	}
	if err := resp.Header.Write(w); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "\r\n"); err != nil {
		return err
	}
	if f, ok := w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

func (s *Server) tunnel(client net.Conn, bufrw *bufio.ReadWriter, upstream net.Conn) {
	if bufrw != nil && bufrw.Reader.Buffered() > 0 {
		n := bufrw.Reader.Buffered()
		b, _ := bufrw.Peek(n)
		_, _ = upstream.Write(b)
		_, _ = bufrw.Discard(n)
	}
	s.setSessionDeadline(client, upstream)
	done := make(chan struct{}, 2)
	go func() {
		s.deadlineCopy(upstream, client)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		s.deadlineCopy(client, upstream)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func (s *Server) setSessionDeadline(conns ...net.Conn) {
	ad := s.specNow().Proxy.Admission
	if ad.SessionTimeout <= 0 {
		return
	}
	dl := time.Now().Add(ad.SessionTimeout)
	for _, c := range conns {
		if c != nil {
			_ = c.SetDeadline(dl)
		}
	}
}

func (s *Server) deadlineCopy(dst io.Writer, src io.Reader) {
	ad := s.specNow().Proxy.Admission
	sessionEnd := time.Time{}
	if ad.SessionTimeout > 0 {
		sessionEnd = time.Now().Add(ad.SessionTimeout)
	}
	idle := ad.IdleTimeout
	if idle <= 0 {
		idle = defaultIdleTimeout
	}
	buf := make([]byte, streamSlack)
	for {
		dl := time.Now().Add(idle)
		if !sessionEnd.IsZero() && dl.After(sessionEnd) {
			dl = sessionEnd
		}
		if rc, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = rc.SetReadDeadline(dl)
		}
		n, err := src.Read(buf)
		if n > 0 {
			if wc, ok := dst.(interface{ SetWriteDeadline(time.Time) error }); ok {
				_ = wc.SetWriteDeadline(dl)
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

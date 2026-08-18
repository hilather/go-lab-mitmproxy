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
)

func (s *Server) serveAbsolute(w http.ResponseWriter, req *http.Request) {
	started := time.Now()
	host, port, err := splitAuthority(req.URL.Host, "80")
	if err != nil {
		writeProxyError(w, http.StatusBadRequest, domainerr.CodeValidationFailed, "invalid authority", "")
		return
	}

	ctx, cancel := context.WithTimeout(req.Context(), s.specNow().Proxy.Admission.UpstreamTimeout)
	defer cancel()

	res, err := resolveThenGuard(ctx, s.resolver, s.specNow().Proxy.Targets, host, port)
	if err != nil {
		s.rejectResolve(w, req, host, err)
		return
	}

	ws := httputilx.IsWebSocketUpgrade(req.Header)
	hadExpect := headerHasExpect(req.Header)
	out, reqCap, err := s.originRequest(ctx, req, res, host, port)
	if err != nil {
		writeProxyError(w, http.StatusBadRequest, domainerr.CodeValidationFailed, err.Error(), "")
		return
	}

	var (
		resp   *http.Response
		sticky net.Conn
	)
	if hadExpect && !ws {
		s.forwardNo100(w, req, out, reqCap, host, started)
		return
	}
	if ws {
		resp, sticky, err = s.roundTripUpgrade(ctx, out, res)
	} else {
		resp, err = s.tr.RoundTrip(out)
	}
	if err != nil {
		s.capture(s.flowFromReq(req, host, "http", 0, "upstream", started))
		writeProxyError(w, http.StatusBadGateway, domainerr.CodeInternalError, "upstream request failed", "")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	websocket := ws && resp.StatusCode == http.StatusSwitchingProtocols
	httputilx.PrepareResponse(resp.Header, websocket)

	if websocket {
		s.hijackUpgrade(w, req, resp, sticky, reqCap, host, started)
		return
	}

	respBody, respCap := teeBody(resp.Body, s.specNow().Store.MaxBodyBytes)
	resp.Body = respBody
	httputilx.CopyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	drainCopy(w, resp.Body)

	f := s.flowFromReq(req, host, "http", resp.StatusCode, "", started)
	f.Protocol = model.FlowProtocolHTTP11
	f.Request.Headers = headersFrom(req.Header)
	if reqCap != nil {
		f.Request.Body = reqCap.buf
		f.Request.Size = len(reqCap.buf)
		f.Request.Truncated = reqCap.truncated
		f.Truncated = f.Truncated || reqCap.truncated
	}
	if respCap != nil {
		f.Response.Headers = headersFrom(resp.Header)
		f.Response.Body = respCap.buf
		f.Response.Size = len(respCap.buf)
		f.Response.Truncated = respCap.truncated
		f.Truncated = f.Truncated || respCap.truncated
	}
	s.capture(f)
	s.metrics.session("ok")
}

func headerHasExpect(h http.Header) bool {
	for _, v := range h.Values("Expect") {
		if strings.EqualFold(strings.TrimSpace(v), "100-continue") {
			return true
		}
	}
	return false
}

// forwardNo100 Hijacks before any body read so net/http cannot emit 100.
func (s *Server) forwardNo100(w http.ResponseWriter, req *http.Request, out *http.Request, reqCap *cappedWriter, host string, started time.Time) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeProxyError(w, http.StatusInternalServerError, domainerr.CodeInternalError, "hijack not supported", "")
		return
	}
	client, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	s.track(client)
	defer s.untrack(client)
	defer func() { _ = client.Close() }()

	var body io.Reader = http.NoBody
	if req.ContentLength > 0 {
		body = io.LimitReader(bufrw, req.ContentLength)
	}
	teed, capw := teeBody(io.NopCloser(body), s.specNow().Store.MaxBodyBytes)
	out.Body = teed
	out.ContentLength = req.ContentLength
	reqCap = capw

	resp, err := s.tr.RoundTrip(out)
	if err != nil {
		s.capture(s.flowFromReq(req, host, "http", 0, "upstream", started))
		writeHijackedError(client, http.StatusBadGateway, domainerr.CodeInternalError, "upstream request failed")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	httputilx.PrepareResponse(resp.Header, false)
	respBody, respCap := teeBody(resp.Body, s.specNow().Store.MaxBodyBytes)
	resp.Body = respBody
	if err := resp.Write(bufrw); err != nil {
		return
	}
	_ = bufrw.Flush()

	f := s.flowFromReq(req, host, "http", resp.StatusCode, "", started)
	if reqCap != nil {
		f.Request.Body = reqCap.buf
		f.Request.Truncated = reqCap.truncated
	}
	if respCap != nil {
		f.Response.Body = respCap.buf
		f.Response.Truncated = respCap.truncated
	}
	s.capture(f)
	s.metrics.session("ok")
}

func (s *Server) originRequest(ctx context.Context, req *http.Request, res resolved, host, port string) (*http.Request, *cappedWriter, error) {
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
	if port != "" && port != "80" {
		out.Host = net.JoinHostPort(host, port)
	} else {
		out.Host = host
	}
	httputilx.PrepareRequest(out.Header)
	max := s.specNow().Store.MaxBodyBytes
	var capw *cappedWriter
	if out.Body != nil {
		var teed io.ReadCloser
		teed, capw = teeBody(out.Body, max)
		out.Body = teed
	}
	return out, capw, nil
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

func (s *Server) roundTripUpgrade(ctx context.Context, out *http.Request, res resolved) (*http.Response, net.Conn, error) {
	var sticky net.Conn
	proto := http1Only()
	tr := &http.Transport{
		Proxy:                 nil,
		DisableCompression:    true,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		Protocols:             proto,
		ResponseHeaderTimeout: s.specNow().Proxy.Admission.UpstreamTimeout,
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
	tunnelUpgrade(client, bufrw, upstream, resp.Body)
}

func tunnelUpgrade(client net.Conn, bufrw *bufio.ReadWriter, upstream net.Conn, fromUp io.Reader) {
	if bufrw != nil && bufrw.Reader.Buffered() > 0 {
		n := bufrw.Reader.Buffered()
		b, _ := bufrw.Peek(n)
		_, _ = upstream.Write(b)
		_, _ = bufrw.Discard(n)
	}
	if fromUp == nil {
		fromUp = upstream
	}
	done := make(chan struct{}, 2)
	go func() {
		drainCopy(upstream, client)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		drainCopy(client, fromUp)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func writeSwitching(bw *bufio.ReadWriter, resp *http.Response) error {
	if _, err := fmt.Fprintf(bw, "HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		return err
	}
	if err := resp.Header.Write(bw); err != nil {
		return err
	}
	if _, err := io.WriteString(bw, "\r\n"); err != nil {
		return err
	}
	return bw.Flush()
}

func tunnel(client net.Conn, bufrw *bufio.ReadWriter, upstream net.Conn) {
	if bufrw != nil && bufrw.Reader.Buffered() > 0 {
		n := bufrw.Reader.Buffered()
		b, _ := bufrw.Peek(n)
		_, _ = upstream.Write(b)
		_, _ = bufrw.Discard(n)
	}
	done := make(chan struct{}, 2)
	go func() {
		drainCopy(upstream, client)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		drainCopy(client, upstream)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

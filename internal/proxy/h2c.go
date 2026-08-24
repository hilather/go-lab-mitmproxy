package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

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
		Preface:              http2x.PrefaceTail,
		MaxConcurrentStreams: maxStreams,
	}, func(ctx context.Context, in http2x.Stream) (*http.Response, []model.Header, error) {
		return s.roundTripH2C(ctx, in, sess, tagged, dest)
	}, nil)
}

func (s *Server) roundTripH2C(ctx context.Context, in http2x.Stream, pinned *ruleSession, tagged bool, dest origDestMeta) (*http.Response, []model.Header, error) {
	if ctx == nil {
		ctx = s.ctx
	}
	if strings.EqualFold(in.Method, http.MethodConnect) {
		if tagged {
			rw := newCaptureRW()
			writeProxyError(rw, http.StatusBadRequest, domainerr.CodeValidationFailed,
				"CONNECT is not supported on original-destination", "")
			return rw.response(), nil, nil
		}
		// RFC 9113 CONNECT (D62) is not tunneled on h2c yet; RST.
		return nil, nil, http2x.ErrInnerCONNECT
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
	if tagged {
		s.serveOrigDestHTTP(rw, inner, dest, sess)
		return rw.response(), nil, nil
	}
	s.serveAbsolute(rw, inner, sess)
	return rw.response(), nil, nil
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

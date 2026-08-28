package proxy

import (
	"net/http"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// ServeHTTP classifies the client request. SOCKS is already gone (peek).
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req == nil {
		return
	}
	if req.Method == "PRI" {
		sess := s.beginSession()
		if !sess.spec.Protocols.HTTP2.ClientCleartext {
			s.metrics.reject("http2")
			s.closeNow(w)
			return
		}
		s.serveH2C(w, req, sess)
		return
	}

	sess := s.beginSession()
	ip := clientIP(req.RemoteAddr)
	if err := s.gate.acquire(ip, sess.spec.Proxy.Admission); err != nil {
		s.metrics.reject("admission")
		if req.Method == http.MethodConnect {
			writeProxyError(w, http.StatusServiceUnavailable, domainerr.CodeRateLimited, "too many sessions", "")
			return
		}
		writeProxyError(w, http.StatusTooManyRequests, domainerr.CodeRateLimited, "too many sessions", "")
		return
	}
	defer s.gate.release(ip)

	if dest, ok := origDestFromContext(req); ok {
		s.metrics.accept()
		if req.Method == http.MethodConnect {
			writeProxyError(w, http.StatusBadRequest, domainerr.CodeValidationFailed,
				"CONNECT is not supported on original-destination", "")
			return
		}
		s.serveOrigDestHTTP(w, req, dest, sess)
		return
	}

	if req.Method == http.MethodConnect && !sess.spec.Protocols.Connect.Enabled {
		s.metrics.reject("connect")
		authority := ""
		if req.URL != nil {
			authority = req.URL.Host
		}
		if authority == "" {
			authority = req.Host
		}
		host, _, err := splitAuthority(authority, "")
		if err != nil || host == "" {
			host = authority
		}
		s.capture(connectFlow(req, host, http.StatusForbidden, string(domainerr.CodeForbidden), time.Now()), sess)
		writeProxyError(w, http.StatusForbidden, domainerr.CodeForbidden, "CONNECT is disabled", "spec.protocols.connect.enabled")
		return
	}

	s.metrics.accept()

	if req.Method == http.MethodConnect {
		s.serveCONNECT(w, req, sess)
		return
	}

	scheme := strings.ToLower(req.URL.Scheme)
	if scheme == "https" {
		s.metrics.reject("absolute_https")
		s.capture(&model.Flow{
			Method:   req.Method,
			URL:      req.URL.String(),
			Host:     req.URL.Host,
			Scheme:   "https",
			Protocol: model.FlowProtocolHTTP11,
			State:    model.FlowStateError,
			Error:    string(domainerr.CodeValidationFailed),
			Status:   http.StatusBadRequest,
		}, sess)
		writeProxyError(w, http.StatusBadRequest, domainerr.CodeValidationFailed,
			"https absolute-form is not supported", "use CONNECT")
		return
	}
	if scheme != "http" || req.URL.Host == "" {
		writeProxyError(w, http.StatusBadRequest, domainerr.CodeValidationFailed,
			"absolute-form or CONNECT required", "")
		return
	}
	s.serveAbsolute(w, req, sess)
}

func (s *Server) closeNow(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	c, _, err := hj.Hijack()
	if err != nil {
		return
	}
	_ = c.Close()
}

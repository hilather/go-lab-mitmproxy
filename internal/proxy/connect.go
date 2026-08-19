package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

const established = "HTTP/1.1 200 Connection Established\r\n\r\n"

func (s *Server) serveCONNECT(w http.ResponseWriter, req *http.Request, sess *ruleSession) {
	started := time.Now()
	if sess == nil {
		sess = s.beginSession()
	}
	// RFC 9110: CONNECT request-target is host:port (req.URL.Host).
	authority := req.URL.Host
	if authority == "" {
		authority = req.Host
	}
	host, port, err := splitAuthority(authority, "")
	if err != nil || port == "" {
		writeProxyError(w, http.StatusBadRequest, domainerr.CodeValidationFailed,
			"CONNECT host:port required", "")
		return
	}

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

	ctx, cancel := context.WithTimeout(s.ctx, sess.spec.Proxy.Admission.UpstreamTimeout)
	defer cancel()

	res, err := resolveThenGuard(ctx, s.resolver, sess.spec.Proxy.Targets, host, port)
	if err != nil {
		s.rejectCONNECT(client, req, host, err, sess)
		return
	}

	up, err := s.dialPinnedTO(ctx, "tcp", pinnedAddr(res.Selected, res.Port), sess.spec.Proxy.Admission.DialTimeout)
	if err != nil {
		s.capture(connectFlow(req, host, http.StatusBadGateway, "dial", started), sess)
		writeHijackedError(client, http.StatusBadGateway, domainerr.CodeInternalError, "dial failed")
		return
	}
	s.track(up)
	defer s.untrack(up)
	defer func() { _ = up.Close() }()

	if bufrw != nil {
		if _, err := io.WriteString(bufrw, established); err != nil {
			return
		}
		if err := bufrw.Flush(); err != nil {
			return
		}
	} else if _, err := io.WriteString(client, established); err != nil {
		return
	}

	if shouldIntercept(sess.spec.TLS, host, port) {
		s.serveInterceptConn(client, bufrw, up, interceptMeta{
			ConnectHost: host,
			Port:        port,
			Res:         res,
			Started:     started,
			ClientReq:   req,
			Via:         "http-proxy",
		}, sess)
		return
	}

	s.capture(connectFlow(req, host, http.StatusOK, "", started), sess)
	s.metrics.session("ok")
	s.tunnel(client, bufrw, up, sess.spec.Proxy.Admission)
}

func (s *Server) rejectCONNECT(c net.Conn, req *http.Request, host string, err error, sess *ruleSession) {
	if isDNS(err) {
		s.capture(connectFlow(req, host, http.StatusBadGateway, "dns", time.Now()), sess)
		writeHijackedError(c, http.StatusBadGateway, domainerr.CodeInternalError, "dns lookup failed")
		return
	}
	s.metrics.reject("target_denied")
	s.capture(connectFlow(req, host, http.StatusForbidden, string(domainerr.CodeTargetDenied), time.Now()), sess)
	writeHijackedError(c, http.StatusForbidden, domainerr.CodeTargetDenied, "target denied")
}

func connectFlow(req *http.Request, host string, status int, ferr string, started time.Time) *model.Flow {
	state := model.FlowStateCompleted
	if ferr != "" {
		state = model.FlowStateError
	}
	method := http.MethodConnect
	if req != nil {
		method = req.Method
	}
	return &model.Flow{
		StartedAt:   started.UTC(),
		CompletedAt: time.Now().UTC(),
		State:       state,
		Method:      method,
		Host:        host,
		Scheme:      "",
		Protocol:    model.FlowProtocolConnect,
		Status:      status,
		Error:       ferr,
		Intercepted: false,
	}
}

// shouldIntercept is the D20 eligibility hook: intercept && listed
// port && (empty hosts || host matches). Handshake failure must not
// fall back to a blind tunnel.
func shouldIntercept(tlsSpec model.TLSSpec, host string, port string) bool {
	if !tlsSpec.Intercept {
		return false
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	if !portListed(tlsSpec.Ports, p) {
		return false
	}
	if len(tlsSpec.Hosts) == 0 {
		return true
	}
	for _, pat := range tlsSpec.Hosts {
		if matchHost(pat, host) {
			return true
		}
	}
	return false
}

func portListed(ports []int, p int) bool {
	if len(ports) == 0 {
		return p == 443
	}
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"

	"github.com/hilather/go-lab-mitmproxy/internal/http2x"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/rules"
)

type ruleResult int

const (
	ruleContinue    ruleResult = iota
	ruleSynthesize             // drop / status / redirect / dropped-breakpoint
	ruleSilentClose            // silent, or hang after timeout
	ruleAbort                  // delay-cancel: end without linger/RST
)

func (r ruleResult) stop() bool {
	return r != ruleContinue
}

func (sess *ruleSession) setCloseMode(hit *rules.Hit) {
	if sess == nil {
		return
	}
	sess.closeMode = rules.SilentClose(hit)
}

func (sess *ruleSession) closeModeOr(def string) string {
	if sess != nil && sess.closeMode != "" {
		return sess.closeMode
	}
	return def
}

// silentCloseHTTP Hijacks a client-facing HTTP/1.1 ResponseWriter and closes
// without HTTP bytes. Returns false when w is not a Hijacker (captureRW).
func (s *Server) silentCloseHTTP(w http.ResponseWriter, mode string) bool {
	if w == nil {
		return false
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return false
	}
	c, _, err := hj.Hijack()
	if err != nil {
		return true
	}
	s.beginHijacked()
	defer s.endHijacked()
	s.track(c)
	defer s.untrack(c)
	silentCloseConn(c, mode)
	return true
}

func silentCloseConn(c net.Conn, mode string) {
	if c == nil {
		return
	}
	if mode != model.SilentCloseFIN {
		if tryFramedRST(c) {
			return
		}
		if tcp := tcpConnOf(c); tcp != nil {
			_ = tcp.SetLinger(0)
			_ = tcp.Close()
			return
		}
	}
	_ = c.Close()
}

func tryFramedRST(c net.Conn) bool {
	for c != nil {
		if http2x.ResetCancel(c) {
			return true
		}
		switch t := c.(type) {
		case *tls.Conn:
			c = t.NetConn()
		case *readerConn:
			c = t.Conn
		case *taggedConn:
			c = t.Conn
		case *peekedConn:
			c = t.Conn
		case *recordingConn:
			c = t.Conn
		default:
			return false
		}
	}
	return false
}

func drainDiscard(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	resp.Body = http.NoBody
}

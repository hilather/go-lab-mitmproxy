package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
)

func writeProxyError(w http.ResponseWriter, status int, code domainerr.Code, msg, remediation string) {
	if w == nil {
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Connection", "close")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "%s: %s\n", code, msg)
	if remediation != "" {
		_, _ = fmt.Fprintf(w, "%s\n", remediation)
	}
}

func innerForbiddenResponse(msg, remediation string) *http.Response {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n", domainerr.CodeForbidden, msg)
	if remediation != "" {
		fmt.Fprintf(&b, "%s\n", remediation)
	}
	body := b.String()
	hdr := make(http.Header)
	hdr.Set("Content-Type", "text/plain; charset=utf-8")
	hdr.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return &http.Response{
		Status:        "403 Forbidden",
		StatusCode:    http.StatusForbidden,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        hdr,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func writeHijackedError(c net.Conn, status int, code domainerr.Code, msg string) {
	if c == nil {
		return
	}
	text := http.StatusText(status)
	if text == "" {
		text = "Error"
	}
	body := fmt.Sprintf("%s: %s\n", code, msg)
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s",
		status, text, len(body), body)
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		return
	}
	type closer interface {
		CloseWrite() error
	}
	if cw, ok := c.(closer); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

func drainCopy(dst io.Writer, src io.Reader) {
	buf := make([]byte, streamSlack)
	_, _ = io.CopyBuffer(dst, src, buf)
}

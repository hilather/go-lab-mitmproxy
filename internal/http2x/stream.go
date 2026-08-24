package http2x

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"golang.org/x/net/http2"
)

const (
	// NextProtoH2 is ALPN "h2".
	NextProtoH2 = "h2"
	// maxConcurrentStreams is the 1.1 default (admission 0 → 100).
	maxConcurrentStreams = 100
	// SettingEnableConnectProtocol is SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441).
	SettingEnableConnectProtocol http2.SettingID = 0x8
	// prefaceHead is the HTTP/1.1 request-line http.Server consumes on PRI
	// (D61 leftover). The 24-byte ClientPreface is prefaceHead + prefaceTailSM.
	prefaceHead   = "PRI * HTTP/2.0\r\n\r\n"
	prefaceTailSM = "SM\r\n\r\n"

	// SettingEnableConnectProtocol is SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441).
	SettingEnableConnectProtocol http2.SettingID = 0x8
)

// ErrRefuseRedial is returned when the origin pool would need a second Dial.
var ErrRefuseRedial = errors.New("proxy: intercepted CONNECT refuses redial")

// ErrInnerCONNECT is returned by a StreamHandler or TunnelHandler to RST the
// stream (inner CONNECT / illegal :protocol, D48 remainder).
var ErrInnerCONNECT = errors.New("http2x: inner CONNECT refused")

// Stream is one HTTP/2 request stream (D45). Pseudos keep their leading ':'.
type Stream struct {
	ID        uint32
	Pseudos   []model.Header
	Headers   []model.Header
	Trailers  []model.Header
	Body      io.ReadCloser
	Method    string
	Scheme    string
	Authority string
	Path      string
	Protocol  string // :protocol
}

// StreamHandler serves one client request stream. The response is encoded as
// HTTP/2; trailers are the returned header list. A non-nil error RSTs the
// stream (errors.Is(err, ErrInnerCONNECT) included).
type StreamHandler func(ctx context.Context, in Stream) (*http.Response, []model.Header, error)

// PrefaceMode selects how ServeConn consumes the HTTP/2 client preface.
type PrefaceMode int

const (
	// PrefaceFull reads the 24-byte ClientPreface from the frame reader
	// (inner ALPN h2 / ServeClient).
	PrefaceFull PrefaceMode = iota
	// PrefaceTail is the PRI Hijack leftover: http.Server already consumed
	// PRI * HTTP/2.0\r\n\r\n. ServeConn must not ReadFull ClientPreface from
	// the raw conn. leftover starts at SM\r\n\r\n plus SETTINGS.
	PrefaceTail
)

// ServeOpts configures ServeConn. Zero value is PrefaceFull, 100 streams,
// no Extended CONNECT, EnablePush off.
// PrefaceMode selects how ServeConn consumes the client connection preface.
type PrefaceMode int

const (
	// PrefaceFull reads the 24-byte ClientPreface (inner ALPN h2).
	PrefaceFull PrefaceMode = iota
	// PrefaceTail skips the 24-byte preface (PRI leftover; not used on inner h2).
	PrefaceTail
)

// ServeOpts configures ServeConn.
type ServeOpts struct {
	Preface               PrefaceMode
	MaxConcurrentStreams  uint32 // snapshot admission; 0 → 100
	EnableConnectProtocol bool
	EnablePush            bool // inner always false
}

// TunnelHandler is CONNECT / Extended CONNECT. Nil tun → those streams go to
// StreamHandler (proxy may RST or return 400). Non-nil: CONNECT skips
// StreamHandler. RFC 9113 CONNECT (D62) is not spliced here: tun is invoked
// then the stream is RST.
type TunnelHandler func(ctx context.Context, in Stream) (Tunnel, error)

// TunnelKind is the post-2xx CONNECT handoff (D62 raw/intercept, D63 websocket).
// TunnelHandler serves CONNECT / :protocol streams. Nil tun on ServeConn
// leaves those streams on StreamHandler (D48 ServeClient path).
type TunnelHandler func(ctx context.Context, in Stream) (Tunnel, error)

// TunnelKind is the post-2xx handoff.
type TunnelKind int

const (
	TunnelRaw TunnelKind = iota
	TunnelIntercept
	TunnelWebSocket
)

// Tunnel is the CONNECT handoff. http2x never Dials.
// Tunnel is the CONNECT handoff. http2x writes :status=200 then AfterAck.
type Tunnel struct {
	Kind     TunnelKind
	Origin   net.Conn
	AfterAck func(client net.Conn)
}

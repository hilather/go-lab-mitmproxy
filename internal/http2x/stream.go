package http2x

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

const (
	// NextProtoH2 is ALPN "h2".
	NextProtoH2 = "h2"
	// maxConcurrentStreams is the 1.1 default (admission 0 → 100).
	maxConcurrentStreams = 100
)

// ErrRefuseRedial is returned when the origin pool would need a second Dial.
var ErrRefuseRedial = errors.New("proxy: intercepted CONNECT refuses redial")

// ErrInnerCONNECT is returned by a StreamHandler to RST the stream
// (inner CONNECT / Extended CONNECT, D48).
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
}

// StreamHandler serves one client request stream. The response is encoded as
// HTTP/2; trailers are the returned header list. A non-nil error RSTs the
// stream (errors.Is(err, ErrInnerCONNECT) included).
type StreamHandler func(ctx context.Context, in Stream) (*http.Response, []model.Header, error)

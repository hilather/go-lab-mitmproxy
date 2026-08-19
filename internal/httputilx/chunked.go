package httputilx

import (
	"io"
	"net/http/httputil"
)

// NewChunkedReader decodes an HTTP/1.1 chunked body. Not ReverseProxy.
func NewChunkedReader(r io.Reader) io.Reader {
	return httputil.NewChunkedReader(r)
}

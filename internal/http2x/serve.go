package http2x

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"golang.org/x/net/http2"
)

var hopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-connection":    true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"proxy-authorization": true,
}

// ServeClient runs an h2 server on client (already ALPN h2). It does not Dial.
// Each request stream invokes h on a goroutine. StreamID is the HTTP/2 stream id.
func ServeClient(ctx context.Context, client *tls.Conn, h StreamHandler) error {
	if client == nil {
		return errors.New("http2x: nil client conn")
	}
	if h == nil {
		return errors.New("http2x: nil StreamHandler")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = client.Close()
	}()

	spy := newFrameSpy(client)
	srv := &http2.Server{MaxConcurrentStreams: maxConcurrentStreams}
	srv.ServeConn(spy, &http2.ServeConnOpts{
		Context: ctx,
		Handler: streamAdapter{h: h, spy: spy},
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

type streamAdapter struct {
	h   StreamHandler
	spy *frameSpy
}

func (a streamAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := a.spy.takeHeadersID()
	in := streamFromRequest(id, r)
	resp, trailers, err := a.h(r.Context(), in)
	if in.Body != nil {
		_, _ = io.Copy(io.Discard, in.Body)
		_ = in.Body.Close()
	}
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if errors.Is(err, ErrInnerCONNECT) {
			panic(http.ErrAbortHandler)
		}
		if resp == nil {
			panic(http.ErrAbortHandler)
		}
	}
	if resp == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	hdr := w.Header()
	if resp.Header != nil {
		for k, vs := range resp.Header {
			lk := strings.ToLower(k)
			if hopHeaders[lk] {
				continue
			}
			for _, v := range vs {
				hdr.Add(k, v)
			}
		}
	}
	for _, th := range trailers {
		if th.Name == "" || hopHeaders[strings.ToLower(th.Name)] {
			continue
		}
		hdr.Add("Trailer", th.Name)
		hdr.Add(http2.TrailerPrefix+th.Name, th.Value)
	}
	status := resp.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if resp.Body != nil {
		_, _ = io.Copy(w, resp.Body)
	}
}

func streamFromRequest(id uint32, r *http.Request) Stream {
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "https"
	}
	authority := r.Host
	path := r.URL.RequestURI()
	if path == "" {
		path = r.URL.Path
		if r.URL.RawQuery != "" {
			path += "?" + r.URL.RawQuery
		}
	}
	if path == "" {
		path = "/"
	}
	pseudos := []model.Header{
		{Name: ":method", Value: r.Method},
		{Name: ":scheme", Value: scheme},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	}
	var headers []model.Header
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if hopHeaders[lk] {
			continue
		}
		for _, v := range vs {
			headers = append(headers, model.Header{Name: k, Value: v})
		}
	}
	body := r.Body
	if body == nil {
		body = http.NoBody
	}
	return Stream{
		ID:        id,
		Pseudos:   pseudos,
		Headers:   headers,
		Body:      body,
		Method:    r.Method,
		Scheme:    scheme,
		Authority: authority,
		Path:      path,
	}
}

// frameSpy tees HEADERS stream IDs. x/net/http2 strips StreamID from http.Request.
type frameSpy struct {
	net.Conn
	mu         sync.Mutex
	buf        []byte
	prefaceOff bool
	ids        []uint32
}

func newFrameSpy(c net.Conn) *frameSpy {
	return &frameSpy{Conn: c}
}

func (s *frameSpy) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if n > 0 {
		s.mu.Lock()
		s.buf = append(s.buf, p[:n]...)
		s.consume()
		s.mu.Unlock()
	}
	return n, err
}

func (s *frameSpy) consume() {
	if !s.prefaceOff {
		if len(s.buf) < len(http2.ClientPreface) {
			return
		}
		s.buf = s.buf[len(http2.ClientPreface):]
		s.prefaceOff = true
	}
	for {
		if len(s.buf) < 9 {
			return
		}
		length := int(s.buf[0])<<16 | int(s.buf[1])<<8 | int(s.buf[2])
		total := 9 + length
		if length < 0 || total < 9 || len(s.buf) < total {
			return
		}
		ftype := s.buf[3]
		sid := binary.BigEndian.Uint32(s.buf[5:9]) & 0x7fffffff
		if ftype == byte(http2.FrameHeaders) && sid != 0 {
			s.ids = append(s.ids, sid)
		}
		s.buf = append([]byte(nil), s.buf[total:]...)
	}
}

func (s *frameSpy) takeHeadersID() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ids) == 0 {
		return 0
	}
	id := s.ids[0]
	s.ids = s.ids[1:]
	return id
}

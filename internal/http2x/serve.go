package http2x

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	maxFramePayload = 16384
	initialWindow   = 1 << 20
)

var hopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-connection":    true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"proxy-authorization": true,
}

type streamState struct {
	body *bodyBuf
}

// ServeClient is request/response-only (extendedConnect off). tun is always
// nil, so CONNECT / :protocol stay on StreamHandler (D48). Inner RFC 8441
// must call ServeConn with a non-nil TunnelHandler.
func ServeClient(ctx context.Context, client *tls.Conn, h StreamHandler) error {
	if client == nil {
		return errors.New("http2x: nil client conn")
	}
	return ServeConn(ctx, client, nil, ServeOpts{Preface: PrefaceFull}, h, nil)
}

func maxStreamsOf(opts ServeOpts) uint32 {
	if opts.MaxConcurrentStreams == 0 {
		return maxConcurrentStreams
	}
	return opts.MaxConcurrentStreams
}

func isTunnelStream(in Stream) bool {
	if strings.EqualFold(in.Method, http.MethodConnect) {
		return true
	}
	return in.Protocol != ""
}

// ServeConn runs an h2 server on c. It does not Dial. leftover may be nil
// when PrefaceFull. Non-nil tun: CONNECT / :protocol skip StreamHandler.
func ServeConn(ctx context.Context, c net.Conn, leftover *bufio.ReadWriter, opts ServeOpts, h StreamHandler, tun TunnelHandler) error {
	if c == nil {
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
		_ = c.Close()
	}()

	br, err := prefaceReader(c, leftover, opts.Preface)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if leftover != nil {
		_ = leftover.Flush()
	}

	fr := http2.NewFramer(c, br)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	fr.MaxHeaderListSize = 1 << 20

	encBuf := new(bytes.Buffer)
	enc := hpack.NewEncoder(encBuf)
	var writeMu sync.Mutex
	write := func(fn func() error) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return fn()
	}

	maxStreams := maxStreamsOf(opts)
	settings := []http2.Setting{
		{ID: http2.SettingMaxConcurrentStreams, Val: maxStreams},
		{ID: http2.SettingInitialWindowSize, Val: initialWindow},
		{ID: http2.SettingEnablePush, Val: 0},
	}
	if opts.EnableConnectProtocol {
		settings = append(settings, http2.Setting{ID: SettingEnableConnectProtocol, Val: 1})
	}

	if err := write(func() error {
		if err := fr.WriteSettings(settings...); err != nil {
			return err
		}
		incr := uint32(initialWindow - 65535)
		if incr > 0 {
			return fr.WriteWindowUpdate(0, incr)
		}
		return nil
	}); err != nil {
		return err
	}

	var (
		mu     sync.Mutex
		open   int
		closed bool
		lastID uint32
	)
	streams := make(map[uint32]*streamState)
	out := newOutFlow()
	defer out.close()

	credit := func(id uint32, n int) {
		if n <= 0 {
			return
		}
		_ = write(func() error {
			if err := fr.WriteWindowUpdate(id, uint32(n)); err != nil {
				return err
			}
			return fr.WriteWindowUpdate(0, uint32(n))
		})
	}

	finish := func(id uint32) {
		mu.Lock()
		if st, ok := streams[id]; ok {
			if st.body != nil {
				_ = st.body.Close()
			}
			delete(streams, id)
			if open > 0 {
				open--
			}
		}
		mu.Unlock()
		out.forget(id)
	}

	for {
		f, err := fr.ReadFrame()
		if err != nil {
			out.close()
			mu.Lock()
			closed = true
			for id, st := range streams {
				if st.body != nil {
					_ = st.body.CloseWithError(io.EOF)
				}
				delete(streams, id)
			}
			mu.Unlock()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || isClosedConn(err) {
				return nil
			}
			var se http2.StreamError
			if errors.As(err, &se) {
				finish(se.StreamID)
				_ = write(func() error { return fr.WriteRSTStream(se.StreamID, se.Code) })
				continue
			}
			return err
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := f.ForeachSetting(func(s http2.Setting) error {
					switch s.ID {
					case http2.SettingInitialWindowSize:
						out.applyInitialWindow(s.Val)
					case http2.SettingMaxFrameSize:
						out.setMaxFrame(s.Val)
					}
					return nil
				}); err != nil {
					return err
				}
				if err := write(fr.WriteSettingsAck); err != nil {
					return err
				}
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				data := f.Data
				if err := write(func() error { return fr.WritePing(true, data) }); err != nil {
					return err
				}
			}
		case *http2.WindowUpdateFrame:
			if f.Increment > 0 {
				out.add(f.StreamID, int32(f.Increment))
			}
		case *http2.RSTStreamFrame:
			finish(f.StreamID)
		case *http2.GoAwayFrame:
			return nil
		case *http2.PushPromiseFrame:
			_ = write(func() error { return fr.WriteRSTStream(f.PromiseID, http2.ErrCodeProtocol) })
		case *http2.DataFrame:
			mu.Lock()
			st := streams[f.StreamID]
			mu.Unlock()
			if st == nil || st.body == nil {
				_ = write(func() error { return fr.WriteRSTStream(f.StreamID, http2.ErrCodeStreamClosed) })
				continue
			}
			if payload := f.Data(); len(payload) > 0 {
				// Non-blocking: bodyBuf.Write never waits for the handler Read.
				if _, err := st.body.Write(append([]byte(nil), payload...)); err != nil {
					finish(f.StreamID)
					_ = write(func() error { return fr.WriteRSTStream(f.StreamID, http2.ErrCodeCancel) })
					continue
				}
			}
			if f.StreamEnded() {
				_ = st.body.Close()
			}
		case *http2.MetaHeadersFrame:
			id := f.StreamID
			if id == 0 || id%2 == 0 {
				return http2.ConnectionError(http2.ErrCodeProtocol)
			}
			mu.Lock()
			if _, exists := streams[id]; exists {
				st := streams[id]
				mu.Unlock()
				// Trailer HEADERS: not a new stream; do not start a handler.
				if st.body != nil {
					_ = st.body.Close()
				}
				continue
			}
			if id <= lastID {
				mu.Unlock()
				_ = write(func() error { return fr.WriteRSTStream(id, http2.ErrCodeProtocol) })
				continue
			}
			if open >= int(maxStreams) {
				mu.Unlock()
				_ = write(func() error { return fr.WriteRSTStream(id, http2.ErrCodeRefusedStream) })
				continue
			}
			lastID = id
			open++
			body := newBodyBuf(func(n int) { credit(id, n) })
			if f.StreamEnded() {
				_ = body.Close()
			}
			streams[id] = &streamState{body: body}
			mu.Unlock()
			out.open(id)

			in := streamFromMeta(id, f, body)
			go func() {
				if tun != nil && isTunnelStream(in) {
					serveTunnel(ctx, tun, in, c, fr, enc, encBuf, write, out, &mu, &closed, finish)
					return
				}
				serveStream(ctx, h, in, func(resp *http.Response, trailers []model.Header, herr error) {
					defer finish(id)
					mu.Lock()
					gone := closed
					mu.Unlock()
					if gone {
						if resp != nil && resp.Body != nil {
							_ = resp.Body.Close()
						}
						return
					}
					if herr != nil || resp == nil {
						code := http2.ErrCodeInternal
						if errors.Is(herr, ErrInnerCONNECT) {
							code = http2.ErrCodeProtocol
						}
						if resp != nil && resp.Body != nil {
							_ = resp.Body.Close()
						}
						_ = write(func() error { return fr.WriteRSTStream(id, code) })
						return
					}
					_ = writeResponse(fr, enc, encBuf, write, out, id, resp, trailers)
				})
			}()
		}
	}
}

func serveStream(ctx context.Context, h StreamHandler, in Stream, done func(*http.Response, []model.Header, error)) {
	defer func() {
		if in.Body != nil {
			_ = in.Body.Close()
		}
	}()
	resp, trailers, err := h(ctx, in)
	done(resp, trailers, err)
}

func serveTunnel(ctx context.Context, tun TunnelHandler, in Stream, parent net.Conn, fr *http2.Framer, enc *hpack.Encoder, encBuf *bytes.Buffer, write func(func() error) error, out *outFlow, mu *sync.Mutex, closed *bool, finish func(uint32)) {
	defer finish(in.ID)
	tunv, err := tun(ctx, in)
	mu.Lock()
	gone := *closed
	mu.Unlock()
	if gone {
		if tunv.AfterAck != nil {
			tunv.AfterAck(&framedStreamConn{parent: parent, id: in.ID, body: in.Body, out: out, fr: fr, write: write})
		}
		return
	}
	if err != nil {
		code := http2.ErrCodeInternal
		if errors.Is(err, ErrInnerCONNECT) {
			code = http2.ErrCodeProtocol
		}
		_ = write(func() error { return fr.WriteRSTStream(in.ID, code) })
		return
	}
	switch tunv.Kind {
	case TunnelWebSocket, TunnelIntercept:
		if tunv.AfterAck == nil {
			_ = write(func() error { return fr.WriteRSTStream(in.ID, http2.ErrCodeInternal) })
			return
		}
		_ = writeStatus(fr, enc, encBuf, write, in.ID, http.StatusOK, false)
		tunv.AfterAck(&framedStreamConn{
			parent: parent,
			id:     in.ID,
			body:   in.Body,
			out:    out,
			fr:     fr,
			write:  write,
		})
	default:
		_ = write(func() error { return fr.WriteRSTStream(in.ID, http2.ErrCodeInternal) })
	}
}

func writeStatus(fr *http2.Framer, enc *hpack.Encoder, buf *bytes.Buffer, write func(func() error) error, id uint32, status int, endStream bool) error {
	return write(func() error {
		buf.Reset()
		if err := enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)}); err != nil {
			return err
		}
		return writeHeaderBlock(fr, id, buf.Bytes(), endStream)
	})
}

func streamFromMeta(id uint32, mh *http2.MetaHeadersFrame, body io.ReadCloser) Stream {
	method := mh.PseudoValue("method")
	scheme := mh.PseudoValue("scheme")
	authority := mh.PseudoValue("authority")
	path := mh.PseudoValue("path")
	protocol := mh.PseudoValue("protocol")
	pseudos := []model.Header{
		{Name: ":method", Value: method},
		{Name: ":scheme", Value: scheme},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	}
	for _, hf := range mh.PseudoFields() {
		switch hf.Name {
		case ":method", ":scheme", ":authority", ":path":
			continue
		default:
			pseudos = append(pseudos, model.Header{Name: strings.Clone(hf.Name), Value: strings.Clone(hf.Value)})
		}
	}
	return Stream{
		ID:        id,
		Pseudos:   pseudos,
		Headers:   cloneFields(mh.RegularFields()),
		Body:      body,
		Method:    method,
		Scheme:    scheme,
		Authority: authority,
		Path:      path,
		Protocol:  protocol,
	}
}

func cloneFields(in []hpack.HeaderField) []model.Header {
	out := make([]model.Header, len(in))
	for i, hf := range in {
		out[i] = model.Header{Name: strings.Clone(hf.Name), Value: strings.Clone(hf.Value)}
	}
	return out
}

func writeResponse(fr *http2.Framer, enc *hpack.Encoder, buf *bytes.Buffer, write func(func() error) error, out *outFlow, id uint32, resp *http.Response, trailers []model.Header) error {
	if resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	status := resp.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	hasBody := resp.Body != nil
	hasTrailers := len(trailers) > 0
	if err := write(func() error {
		buf.Reset()
		if err := enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)}); err != nil {
			return err
		}
		if resp.Header != nil {
			for k, vs := range resp.Header {
				lk := strings.ToLower(k)
				if hopHeaders[lk] || lk == "host" {
					continue
				}
				for _, v := range vs {
					if err := enc.WriteField(hpack.HeaderField{Name: lk, Value: v}); err != nil {
						return err
					}
				}
			}
		}
		return writeHeaderBlock(fr, id, buf.Bytes(), !hasBody && !hasTrailers)
	}); err != nil {
		return err
	}
	if hasBody {
		chunk := make([]byte, maxFramePayload)
		sawEnd := false
		for {
			n, err := resp.Body.Read(chunk)
			if n > 0 {
				off := 0
				for off < n {
					take, werr := out.take(id, n-off)
					if werr != nil {
						return werr
					}
					end := err == io.EOF && off+take == n && !hasTrailers
					payload := append([]byte(nil), chunk[off:off+take]...)
					if werr := write(func() error {
						return fr.WriteData(id, end, payload)
					}); werr != nil {
						return werr
					}
					if end {
						sawEnd = true
					}
					off += take
				}
			}
			if err == io.EOF {
				if !hasTrailers && !sawEnd {
					if werr := write(func() error {
						return fr.WriteData(id, true, nil)
					}); werr != nil {
						return werr
					}
				}
				break
			}
			if err != nil {
				return err
			}
		}
	}
	if hasTrailers {
		return write(func() error {
			buf.Reset()
			for _, th := range trailers {
				name := strings.ToLower(th.Name)
				if name == "" || hopHeaders[name] {
					continue
				}
				if err := enc.WriteField(hpack.HeaderField{Name: name, Value: th.Value}); err != nil {
					return err
				}
			}
			return writeHeaderBlock(fr, id, buf.Bytes(), true)
		})
	}
	return nil
}

func writeHeaderBlock(fr *http2.Framer, id uint32, block []byte, endStream bool) error {
	if len(block) == 0 {
		return fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      id,
			BlockFragment: block,
			EndHeaders:    true,
			EndStream:     endStream,
		})
	}
	first := true
	for len(block) > 0 {
		n := len(block)
		if n > maxFramePayload {
			n = maxFramePayload
		}
		chunk := block[:n]
		block = block[n:]
		endHeaders := len(block) == 0
		if first {
			first = false
			if err := fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      id,
				BlockFragment: chunk,
				EndHeaders:    endHeaders,
				EndStream:     endStream && endHeaders,
			}); err != nil {
				return err
			}
			continue
		}
		if err := fr.WriteContinuation(id, endHeaders, chunk); err != nil {
			return err
		}
	}
	return nil
}

func isClosedConn(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "tls: failed to send closeNotify")
}

// prefaceReader consumes the 24-byte client preface then returns the remainder.
// PrefaceTail (D61 leftover): leftover.Reader starts at SM\r\n\r\n.
// Must not ReadFull ClientPreface from the raw conn.
func prefaceReader(c net.Conn, leftover *bufio.ReadWriter, mode PrefaceMode) (io.Reader, error) {
	var r io.Reader
	if leftover != nil && leftover.Reader != nil {
		r = leftover.Reader
	} else {
		if mode == PrefaceTail {
			return nil, errors.New("http2x: PrefaceTail requires leftover")
		}
		r = bufio.NewReader(c)
	}
	if mode == PrefaceTail {
		r = io.MultiReader(strings.NewReader(prefaceHead), r)
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(r, preface); err != nil {
		return nil, err
	}
	if string(preface) != http2.ClientPreface {
		return nil, fmt.Errorf("http2x: bad client preface")
	}
	return r, nil
}

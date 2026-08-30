package http2x

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// OriginOpts configures the origin Framer client (D64/D65).
type OriginOpts struct {
	CapturePush bool
	MaxBody     int // 0 = unbounded capture of promised DATA
	OnPush      func(Pushed)
	OnRST       func()
}

// Pushed is one origin PUSH_PROMISE stream captured for the flow store.
// It is never forwarded to the inner client.
type Pushed struct {
	ParentStreamID    uint32
	PromisedID        uint32
	Method            string
	Scheme            string
	Authority         string
	Path              string
	RequestHeaders    []model.Header
	ResponseHeaders   []model.Header
	Status            int
	ResponseBody      []byte
	ResponseTruncated bool
}

type originStream struct {
	id       uint32
	body     *bodyBuf
	hdr      chan []hpack.HeaderField
	fail     chan error
	closed   atomic.Bool
	gotResp  atomic.Bool
	trailers []hpack.HeaderField
	trMu     sync.Mutex
}

func (st *originStream) storeTrailers(fields []hpack.HeaderField) {
	if st == nil {
		return
	}
	st.trMu.Lock()
	st.trailers = fields
	st.trMu.Unlock()
}

func (st *originStream) takeTrailers() []hpack.HeaderField {
	if st == nil {
		return nil
	}
	st.trMu.Lock()
	defer st.trMu.Unlock()
	return st.trailers
}

// trailerBody copies origin trailing HEADERS onto resp.Trailer after
// the body is drained (stdlib convention: Trailer is filled at EOF/Close).
type trailerBody struct {
	io.ReadCloser
	st   *originStream
	dest *http.Header
	once sync.Once
}

func (b *trailerBody) promote() {
	b.once.Do(func() {
		if b.dest == nil {
			return
		}
		h := make(http.Header)
		for _, hf := range b.st.takeTrailers() {
			lk := strings.ToLower(hf.Name)
			if lk == "" || strings.HasPrefix(lk, ":") || hopHeaders[lk] || lk == "trailer" {
				continue
			}
			h.Add(hf.Name, hf.Value)
		}
		*b.dest = h
	})
}

func (b *trailerBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.promote()
	}
	return n, err
}

func (b *trailerBody) Close() error {
	err := b.ReadCloser.Close()
	b.promote()
	return err
}

type pushStream struct {
	parent    uint32
	id        uint32
	req       []model.Header
	method    string
	scheme    string
	authority string
	path      string
	status    int
	resp      []model.Header
	body      []byte
	trunc     bool
	gotResp   bool
}

// OriginConn is an HTTP/2 client bound to an already-dialed origin conn.
// It never Dials. ENABLE_PUSH is 1 only when CapturePush; else 0 (D65).
type OriginConn struct {
	c    net.Conn
	opts OriginOpts

	fr     *http2.Framer
	dec    *hpack.Decoder
	enc    *hpack.Encoder
	encBuf *bytes.Buffer
	write  func(func() error) error
	out    *outFlow

	mu      sync.Mutex
	nextID  uint32
	streams map[uint32]*originStream
	pushes  map[uint32]*pushStream
	closed  bool
	err     error
}

// NewOriginConn binds an origin Framer client to up. up must already be dialed.
func NewOriginConn(up net.Conn, opts OriginOpts) (*OriginConn, error) {
	if up == nil {
		return nil, ErrRefuseRedial
	}
	if _, err := io.WriteString(up, http2.ClientPreface); err != nil {
		return nil, err
	}
	fr := http2.NewFramer(up, up)
	dec := hpack.NewDecoder(4096, nil)
	fr.ReadMetaHeaders = dec
	fr.MaxHeaderListSize = 1 << 20
	encBuf := new(bytes.Buffer)
	enc := hpack.NewEncoder(encBuf)
	var writeMu sync.Mutex
	o := &OriginConn{
		c:       up,
		opts:    opts,
		fr:      fr,
		dec:     dec,
		enc:     enc,
		encBuf:  encBuf,
		out:     newOutFlow(),
		nextID:  1,
		streams: make(map[uint32]*originStream),
		pushes:  make(map[uint32]*pushStream),
	}
	o.write = func(fn func() error) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return fn()
	}
	enablePush := uint32(0)
	if opts.CapturePush {
		enablePush = 1
	}
	if err := o.write(func() error {
		if err := fr.WriteSettings(
			http2.Setting{ID: http2.SettingEnablePush, Val: enablePush},
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: initialWindow},
			http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: maxConcurrentStreams},
		); err != nil {
			return err
		}
		incr := uint32(initialWindow - 65535)
		if incr > 0 {
			return fr.WriteWindowUpdate(0, incr)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	go o.readLoop()
	return o, nil
}

// RoundTrip multiplexes one request on the pinned origin TCP. A closed
// conn or a second open after GOAWAY returns ErrRefuseRedial.
func (o *OriginConn) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, ErrRefuseRedial
	}
	o.mu.Lock()
	if o.closed {
		err := o.err
		o.mu.Unlock()
		if err == nil {
			err = ErrRefuseRedial
		}
		return nil, err
	}
	id := o.nextID
	if id == 0 || id%2 == 0 || id > 1<<31-1 {
		o.mu.Unlock()
		return nil, ErrRefuseRedial
	}
	o.nextID += 2
	st := &originStream{
		id:   id,
		body: newBodyBuf(func(n int) { o.credit(id, n) }),
		hdr:  make(chan []hpack.HeaderField, 1),
		fail: make(chan error, 1),
	}
	o.streams[id] = st
	o.mu.Unlock()
	o.out.open(id)

	hasBody := requestHasBody(req)
	if err := o.write(func() error {
		o.encBuf.Reset()
		if err := encodeOriginRequest(o.enc, req); err != nil {
			return err
		}
		return writeHeaderBlock(o.fr, id, o.encBuf.Bytes(), !hasBody)
	}); err != nil {
		o.forget(id)
		return nil, err
	}
	if hasBody {
		go o.writeRequestBody(id, req.Body)
	}

	ctx := req.Context()
	select {
	case <-ctx.Done():
		o.reset(id, http2.ErrCodeCancel)
		o.forget(id)
		return nil, ctx.Err()
	case err := <-st.fail:
		o.forget(id)
		if err == nil {
			err = ErrRefuseRedial
		}
		return nil, err
	case fields, ok := <-st.hdr:
		if !ok {
			o.forget(id)
			return nil, ErrRefuseRedial
		}
		resp := responseFromFields(fields, st.body)
		resp.Trailer = make(http.Header)
		resp.Body = &trailerBody{ReadCloser: resp.Body, st: st, dest: &resp.Trailer}
		return resp, nil
	}
}

// requestHasBody matches net/http.Request.outgoingLength: a non-nil Body
// with ContentLength 0 is unknown-length, not "no body". Inner h2
// reconstruct leaves ContentLength 0 while teeing stream DATA (gRPC and
// most h2 POSTs omit content-length).
func requestHasBody(req *http.Request) bool {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return false
	}
	return true
}

func (o *OriginConn) writeRequestBody(id uint32, body io.ReadCloser) {
	if body == nil {
		return
	}
	defer func() { _ = body.Close() }()
	chunk := make([]byte, maxFramePayload)
	sawEnd := false
	for {
		n, err := body.Read(chunk)
		if n > 0 {
			off := 0
			for off < n {
				take, werr := o.out.take(id, n-off)
				if werr != nil {
					o.reset(id, http2.ErrCodeCancel)
					return
				}
				end := err == io.EOF && off+take == n
				payload := append([]byte(nil), chunk[off:off+take]...)
				if werr := o.write(func() error {
					return o.fr.WriteData(id, end, payload)
				}); werr != nil {
					return
				}
				if end {
					sawEnd = true
				}
				off += take
			}
		}
		if err == io.EOF {
			if !sawEnd {
				_ = o.write(func() error { return o.fr.WriteData(id, true, nil) })
			}
			return
		}
		if err != nil {
			o.reset(id, http2.ErrCodeCancel)
			return
		}
	}
}

func (o *OriginConn) credit(id uint32, n int) {
	if n <= 0 {
		return
	}
	_ = o.write(func() error {
		if err := o.fr.WriteWindowUpdate(id, uint32(n)); err != nil {
			return err
		}
		return o.fr.WriteWindowUpdate(0, uint32(n))
	})
}

// creditConn restores only the connection receive window. Stream WINDOW_UPDATE
// after END_STREAM or RST is unused; the hop-by-hop connection window is not.
func (o *OriginConn) creditConn(n int) {
	if n <= 0 {
		return
	}
	_ = o.write(func() error {
		return o.fr.WriteWindowUpdate(0, uint32(n))
	})
}

func (o *OriginConn) reset(id uint32, code http2.ErrCode) {
	_ = o.write(func() error { return o.fr.WriteRSTStream(id, code) })
}

func (o *OriginConn) forget(id uint32) {
	o.mu.Lock()
	if st, ok := o.streams[id]; ok {
		delete(o.streams, id)
		if st.body != nil && !st.closed.Load() {
			_ = st.body.Close()
		}
	}
	delete(o.pushes, id)
	o.mu.Unlock()
	o.out.forget(id)
}

func (o *OriginConn) failAll(err error) {
	if err == nil {
		err = ErrRefuseRedial
	}
	o.out.close()
	o.mu.Lock()
	o.closed = true
	o.err = err
	for id, st := range o.streams {
		select {
		case st.fail <- err:
		default:
		}
		if st.body != nil {
			_ = st.body.CloseWithError(err)
		}
		delete(o.streams, id)
	}
	o.pushes = map[uint32]*pushStream{}
	o.mu.Unlock()
}

func (o *OriginConn) readLoop() {
	defer o.failAll(io.EOF)
	for {
		f, err := o.fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = f.ForeachSetting(func(s http2.Setting) error {
					switch s.ID {
					case http2.SettingInitialWindowSize:
						o.out.applyInitialWindow(s.Val)
					case http2.SettingMaxFrameSize:
						o.out.setMaxFrame(s.Val)
					}
					return nil
				})
				_ = o.write(o.fr.WriteSettingsAck)
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				data := f.Data
				_ = o.write(func() error { return o.fr.WritePing(true, data) })
			}
		case *http2.WindowUpdateFrame:
			if f.Increment > 0 {
				o.out.add(f.StreamID, int32(f.Increment))
			}
		case *http2.GoAwayFrame:
			return
		case *http2.RSTStreamFrame:
			o.failStream(f.StreamID, fmt.Errorf("http2x: RST_STREAM %v", f.ErrCode))
		case *http2.PushPromiseFrame:
			o.handlePushPromise(f)
		case *http2.MetaHeadersFrame:
			o.handleHeaders(f)
		case *http2.HeadersFrame:
			// ReadMetaHeaders normally merges these; leftover is a protocol error.
			o.reset(f.StreamID, http2.ErrCodeProtocol)
		case *http2.DataFrame:
			o.handleData(f)
		}
	}
}

func (o *OriginConn) failStream(id uint32, err error) {
	o.mu.Lock()
	st := o.streams[id]
	delete(o.streams, id)
	delete(o.pushes, id)
	o.mu.Unlock()
	if st != nil {
		select {
		case st.fail <- err:
		default:
		}
		if st.body != nil {
			_ = st.body.CloseWithError(err)
		}
	}
	o.out.forget(id)
}

func (o *OriginConn) handleHeaders(f *http2.MetaHeadersFrame) {
	id := f.StreamID
	fields := cloneHPACK(f.Fields)
	o.mu.Lock()
	st := o.streams[id]
	ps := o.pushes[id]
	o.mu.Unlock()
	if st != nil {
		if status := statusOf(fields); status > 0 && status < 200 {
			// 1xx informational HEADERS must not become the RoundTrip
			// response or steal the trailer slot from the final status.
			if f.StreamEnded() {
				o.failStream(id, fmt.Errorf("http2x: informational HEADERS ended stream"))
			}
			return
		}
		if st.gotResp.Swap(true) {
			st.storeTrailers(fields)
		} else {
			select {
			case st.hdr <- fields:
			default:
				st.storeTrailers(fields)
			}
		}
		if f.StreamEnded() && st.body != nil {
			_ = st.body.Close()
			st.closed.Store(true)
		}
		return
	}
	if ps != nil {
		if !ps.gotResp {
			ps.gotResp = true
			ps.resp = modelHeaders(fields)
			ps.status = statusOf(fields)
		}
		if f.StreamEnded() {
			o.finishPush(ps, true)
		}
		return
	}
	o.reset(id, http2.ErrCodeStreamClosed)
}

func (o *OriginConn) handleData(f *http2.DataFrame) {
	id := f.StreamID
	payload := append([]byte(nil), f.Data()...)
	o.mu.Lock()
	st := o.streams[id]
	ps := o.pushes[id]
	o.mu.Unlock()
	if st != nil && st.body != nil {
		if len(payload) > 0 {
			if _, err := st.body.Write(payload); err != nil {
				o.reset(id, http2.ErrCodeCancel)
				o.failStream(id, err)
				return
			}
		}
		if f.StreamEnded() {
			_ = st.body.Close()
			st.closed.Store(true)
		}
		return
	}
	if ps != nil {
		if len(payload) > 0 {
			max := o.opts.MaxBody
			if max > 0 && len(ps.body)+len(payload) > max {
				keep := max - len(ps.body)
				if keep > 0 {
					ps.body = append(ps.body, payload[:keep]...)
				}
				ps.trunc = true
				o.creditConn(len(payload))
				o.finishPush(ps, false)
				return
			}
			ps.body = append(ps.body, payload...)
		}
		if f.StreamEnded() {
			o.creditConn(len(payload))
			o.finishPush(ps, true)
			return
		}
		if len(payload) > 0 {
			o.credit(id, len(payload))
		}
		return
	}
	if len(payload) > 0 {
		o.credit(id, len(payload))
	}
	o.reset(id, http2.ErrCodeStreamClosed)
}

func (o *OriginConn) handlePushPromise(f *http2.PushPromiseFrame) {
	promised := f.PromiseID
	parent := f.StreamID
	frag := append([]byte(nil), f.HeaderBlockFragment()...)
	if len(frag) > maxPushHeaderBlock {
		o.failAll(http2.ConnectionError(http2.ErrCodeProtocol))
		return
	}
	ended := f.HeadersEnded()
	for !ended {
		nf, err := o.fr.ReadFrame()
		if err != nil {
			o.failAll(err)
			return
		}
		cf, ok := nf.(*http2.ContinuationFrame)
		if !ok || cf.StreamID != parent {
			o.failAll(http2.ConnectionError(http2.ErrCodeProtocol))
			return
		}
		next := cf.HeaderBlockFragment()
		if len(frag)+len(next) > maxPushHeaderBlock {
			o.failAll(http2.ConnectionError(http2.ErrCodeProtocol))
			return
		}
		frag = append(frag, next...)
		ended = cf.HeadersEnded()
	}
	fields, err := decodeHPACK(o.dec, frag)
	if err != nil {
		o.failAll(err)
		return
	}
	if !o.opts.CapturePush {
		o.reset(promised, http2.ErrCodeCancel)
		if o.opts.OnRST != nil {
			o.opts.OnRST()
		}
		return
	}
	ps := &pushStream{
		parent:    parent,
		id:        promised,
		req:       modelHeaders(fields),
		method:    pseudoValue(fields, ":method"),
		scheme:    pseudoValue(fields, ":scheme"),
		authority: pseudoValue(fields, ":authority"),
		path:      pseudoValue(fields, ":path"),
	}
	o.mu.Lock()
	o.pushes[promised] = ps
	o.mu.Unlock()
	o.out.open(promised)
}

func (o *OriginConn) finishPush(ps *pushStream, ended bool) {
	if ps == nil {
		return
	}
	o.mu.Lock()
	_, still := o.pushes[ps.id]
	delete(o.pushes, ps.id)
	o.mu.Unlock()
	if !still {
		return
	}
	if !ended {
		o.reset(ps.id, http2.ErrCodeCancel)
	}
	o.out.forget(ps.id)
	if o.opts.OnPush == nil {
		return
	}
	p := Pushed{
		ParentStreamID:    ps.parent,
		PromisedID:        ps.id,
		Method:            ps.method,
		Scheme:            ps.scheme,
		Authority:         ps.authority,
		Path:              ps.path,
		RequestHeaders:    ps.req,
		ResponseHeaders:   ps.resp,
		Status:            ps.status,
		ResponseBody:      append([]byte(nil), ps.body...),
		ResponseTruncated: ps.trunc,
	}
	go o.opts.OnPush(p)
}

func encodeOriginRequest(enc *hpack.Encoder, req *http.Request) error {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	scheme := "https"
	if req.URL != nil && req.URL.Scheme != "" {
		scheme = req.URL.Scheme
	}
	authority := req.Host
	if authority == "" && req.URL != nil {
		authority = req.URL.Host
	}
	path := "/"
	if req.URL != nil {
		if p := req.URL.RequestURI(); p != "" {
			path = p
		}
	}
	protocol := ""
	if req.Header != nil {
		protocol = req.Header.Get(":protocol")
	}
	if err := enc.WriteField(hpack.HeaderField{Name: ":method", Value: method}); err != nil {
		return err
	}
	extended := protocol != ""
	connect := strings.EqualFold(method, http.MethodConnect)
	if !connect || extended {
		if err := enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: scheme}); err != nil {
			return err
		}
		if err := enc.WriteField(hpack.HeaderField{Name: ":path", Value: path}); err != nil {
			return err
		}
	}
	if err := enc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority}); err != nil {
		return err
	}
	if extended {
		if err := enc.WriteField(hpack.HeaderField{Name: ":protocol", Value: protocol}); err != nil {
			return err
		}
	}
	if req.Header == nil {
		return nil
	}
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		if lk == "" || strings.HasPrefix(lk, ":") || hopHeaders[lk] || lk == "host" {
			continue
		}
		for _, v := range vs {
			if err := enc.WriteField(hpack.HeaderField{Name: lk, Value: v}); err != nil {
				return err
			}
		}
	}
	return nil
}

func responseFromFields(fields []hpack.HeaderField, body io.ReadCloser) *http.Response {
	hdr := make(http.Header)
	status := http.StatusOK
	for _, hf := range fields {
		if hf.Name == ":status" {
			if n, err := strconv.Atoi(hf.Value); err == nil && n > 0 {
				status = n
			}
			continue
		}
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		hdr.Add(hf.Name, hf.Value)
	}
	if body == nil {
		body = http.NoBody
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		Header:        hdr,
		Body:          body,
		ContentLength: -1,
	}
}

func cloneHPACK(in []hpack.HeaderField) []hpack.HeaderField {
	out := make([]hpack.HeaderField, len(in))
	for i, hf := range in {
		out[i] = hpack.HeaderField{Name: strings.Clone(hf.Name), Value: strings.Clone(hf.Value)}
	}
	return out
}

func modelHeaders(fields []hpack.HeaderField) []model.Header {
	out := make([]model.Header, len(fields))
	for i, hf := range fields {
		out[i] = model.Header{Name: strings.Clone(hf.Name), Value: strings.Clone(hf.Value)}
	}
	return out
}

func pseudoValue(fields []hpack.HeaderField, name string) string {
	for _, hf := range fields {
		if hf.Name == name {
			return hf.Value
		}
	}
	return ""
}

func statusOf(fields []hpack.HeaderField) int {
	v := pseudoValue(fields, ":status")
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

func decodeHPACK(dec *hpack.Decoder, frag []byte) ([]hpack.HeaderField, error) {
	var fields []hpack.HeaderField
	dec.SetEmitEnabled(true)
	dec.SetEmitFunc(func(hf hpack.HeaderField) {
		fields = append(fields, hpack.HeaderField{
			Name:  strings.Clone(hf.Name),
			Value: strings.Clone(hf.Value),
		})
	})
	defer dec.SetEmitFunc(func(hpack.HeaderField) {})
	if _, err := dec.Write(frag); err != nil {
		return nil, err
	}
	if err := dec.Close(); err != nil {
		return nil, err
	}
	return fields, nil
}

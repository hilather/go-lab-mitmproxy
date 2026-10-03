package http2x

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestStreamHeaderErrorPreservesConnection(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		_ = ServeClient(ctx, server, func(context.Context, Stream) (*http.Response, []model.Header, error) {
			return &http.Response{StatusCode: 200}, nil, nil
		})
	}()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(client, http2.ClientPreface)
	fr := http2.NewFramer(client, client)
	_ = fr.WriteSettings()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, id := range []uint32{1, 3} {
		buf.Reset()
		for _, hf := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "app.lab"}, {Name: ":path", Value: "/"}} {
			_ = enc.WriteField(hf)
		}
		if id == 1 {
			_ = enc.WriteField(hpack.HeaderField{Name: "Uppercase", Value: "invalid"})
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: buf.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
			t.Fatal(err)
		}
	}
	var reset bool
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		switch f := f.(type) {
		case *http2.RSTStreamFrame:
			if f.StreamID == 1 {
				reset = true
			}
		case *http2.HeadersFrame:
			if f.StreamID == 3 {
				if !reset {
					t.Fatal("missing reset")
				}
				return
			}
		}
	}
}

func TestOriginCompletedStreamsRetired(t *testing.T) {
	client, server := h2TLSPair(t)
	go (&http2.Server{}).ServeConn(server, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })})
	oc, err := NewOriginConn(client, OriginOpts{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://app.lab/", nil)
		resp, err := oc.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	oc.mu.Lock()
	n := len(oc.streams)
	oc.mu.Unlock()
	oc.out.mu.Lock()
	out := len(oc.out.stream)
	oc.out.mu.Unlock()
	if n != 0 || out != 0 {
		t.Fatalf("completed streams retained: receive=%d send=%d", n, out)
	}
}

func TestReceiveWindowsRejectExcessAndRestoreCredits(t *testing.T) {
	f := newInFlow()
	f.open(1)
	f.open(3)
	if err := f.take(1, initialWindow); err != nil {
		t.Fatal(err)
	}
	if err := f.take(3, 1); err != http2.ConnectionError(http2.ErrCodeFlowControl) {
		t.Fatalf("connection overflow: %v", err)
	}
	f.credit(0, initialWindow)
	err := f.take(1, 1)
	if se, ok := err.(http2.StreamError); !ok || se.Code != http2.ErrCodeFlowControl {
		t.Fatalf("stream overflow: %v", err)
	}
	f.credit(0, 1)
	f.forget(1)
	if err := f.take(1, initialWindow); err != nil {
		t.Fatal(err)
	}
	f.credit(0, initialWindow)
	if err := f.take(3, initialWindow); err != nil {
		t.Fatal(err)
	}
}

func TestServeUnreadDATAExceedsConnectionWindow(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ServeClient(ctx, server, func(ctx context.Context, in Stream) (*http.Response, []model.Header, error) {
			<-ctx.Done()
			return nil, nil, ctx.Err()
		})
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(client, http2.ClientPreface)
	fr := http2.NewFramer(client, client)
	go func() {
		for {
			if _, err := fr.ReadFrame(); err != nil {
				return
			}
		}
	}()
	_ = fr.WriteSettings()
	var b bytes.Buffer
	enc := hpack.NewEncoder(&b)
	for _, hf := range []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "app.lab"}, {Name: ":path", Value: "/"}} {
		_ = enc.WriteField(hf)
	}
	_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: b.Bytes(), EndHeaders: true})
	payload := bytes.Repeat([]byte("x"), maxFramePayload)
	for i := 0; i <= initialWindow/maxFramePayload; i++ {
		if err := fr.WriteData(1, false, payload); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-done:
		if err != http2.ConnectionError(http2.ErrCodeFlowControl) {
			t.Fatalf("overflow error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("unread DATA exceeded advertised receive window")
	}
}

func TestOriginUnreadDATAExceedsConnectionWindow(t *testing.T) {
	client, server := h2TLSPair(t)
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		preface := make([]byte, len(http2.ClientPreface))
		_, _ = io.ReadFull(server, preface)
		fr := http2.NewFramer(server, server)
		ready := make(chan uint32, 1)
		go func() {
			for {
				f, err := fr.ReadFrame()
				if err != nil {
					return
				}
				if hf, ok := f.(*http2.HeadersFrame); ok {
					ready <- hf.StreamID
					return
				}
			}
		}()
		_ = fr.WriteSettings()
		id := <-ready
		go func() {
			for {
				if _, err := fr.ReadFrame(); err != nil {
					return
				}
			}
		}()
		var b bytes.Buffer
		enc := hpack.NewEncoder(&b)
		_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: b.Bytes(), EndHeaders: true})
		payload := bytes.Repeat([]byte("x"), maxFramePayload)
		for i := 0; i <= initialWindow/maxFramePayload; i++ {
			if err := fr.WriteData(id, false, payload); err != nil {
				return
			}
		}
	}()
	oc, err := NewOriginConn(client, OriginOpts{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://app.lab/", nil)
	resp, err := oc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	for {
		oc.mu.Lock()
		closed, e := oc.closed, oc.err
		oc.mu.Unlock()
		if closed {
			if e != http2.ConnectionError(http2.ErrCodeFlowControl) {
				t.Fatalf("overflow error: %v", e)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("origin accepted excess unread DATA")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestOriginPaddedDATAReceiveCredits(t *testing.T) {
	var wire, output bytes.Buffer
	writer := http2.NewFramer(&wire, nil)
	if err := writer.WriteDataPadded(1, false, []byte("abc"), make([]byte, 20)); err != nil {
		t.Fatal(err)
	}
	frame, err := http2.NewFramer(nil, &wire).ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	oc := &OriginConn{inbound: newInFlow(), out: newOutFlow(), streams: make(map[uint32]*originStream), pushes: make(map[uint32]*pushStream)}
	oc.fr = http2.NewFramer(&output, nil)
	oc.write = func(fn func() error) error { return fn() }
	oc.inbound.open(1)
	oc.out.open(1)
	st := &originStream{id: 1, body: newBodyBuf(func(n int) { oc.credit(1, n) }), fail: make(chan error, 1)}
	oc.streams[1] = st
	oc.handleData(frame.(*http2.DataFrame))
	oc.inbound.mu.Lock()
	conn, stream := oc.inbound.conn, oc.inbound.stream[1]
	oc.inbound.mu.Unlock()
	if conn != initialWindow-3 || stream != initialWindow-3 {
		t.Fatalf("padding credit: connection=%d stream=%d", conn, stream)
	}
	oc.failStream(1, io.ErrClosedPipe)
	oc.inbound.mu.Lock()
	conn = oc.inbound.conn
	oc.inbound.mu.Unlock()
	if conn != initialWindow {
		t.Fatalf("RST unread credit=%d", conn)
	}
	p := make([]byte, 3)
	_, _ = st.body.Read(p)
	oc.inbound.mu.Lock()
	conn = oc.inbound.conn
	oc.inbound.mu.Unlock()
	if conn != initialWindow {
		t.Fatalf("double credit after RST=%d", conn)
	}
}

func TestRSTCancelsHandlerContext(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	entered := make(chan struct{})
	canceled := make(chan struct{})
	go func() {
		_ = ServeClient(ctx, server, func(ctx context.Context, in Stream) (*http.Response, []model.Header, error) {
			close(entered)
			<-ctx.Done()
			close(canceled)
			return nil, nil, ctx.Err()
		})
	}()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(client, http2.ClientPreface)
	fr := http2.NewFramer(client, client)
	go func() {
		for {
			if _, err := fr.ReadFrame(); err != nil {
				return
			}
		}
	}()
	_ = fr.WriteSettings()
	var b bytes.Buffer
	enc := hpack.NewEncoder(&b)
	for _, hf := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "app.lab"}, {Name: ":path", Value: "/"}} {
		_ = enc.WriteField(hf)
	}
	_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: b.Bytes(), EndHeaders: true, EndStream: true})
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("handler not started")
	}
	_ = fr.WriteRSTStream(1, http2.ErrCodeCancel)
	select {
	case <-canceled:
	case <-ctx.Done():
		t.Fatal("RST did not cancel stream handler context")
	}
}

type failedResponseReader struct{}

func (failedResponseReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestResponseBodyFailureResetsOnlyStream(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		_ = ServeClient(ctx, server, func(_ context.Context, in Stream) (*http.Response, []model.Header, error) {
			var body io.Reader = bytes.NewBufferString("ok")
			if in.Path == "/broken" {
				body = io.MultiReader(bytes.NewBufferString("first"), failedResponseReader{})
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(body)}, nil, nil
		})
	}()
	cc, err := (&http2.Transport{}).NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://app.lab/broken", nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err == nil {
		t.Fatalf("failed body completed without RST: %q", b)
	}
	req, _ = http.NewRequestWithContext(ctx, "GET", "https://app.lab/ok", nil)
	resp, err = cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	b, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(b) != "ok" {
		t.Fatalf("next stream=%q err=%v", b, err)
	}
}

func TestOriginResponseCloseAbortsUploadAndRetiresStream(t *testing.T) {
	client, server := h2TLSPair(t)
	go (&http2.Server{}).ServeConn(server, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stall" {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, "next")
	})})
	oc, err := NewOriginConn(client, OriginOpts{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	upload := newBodyBuf(nil)
	defer func() { _ = upload.Close() }()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.lab/stall", upload)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := oc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !upload.Closed() {
		t.Fatal("aborted origin response left upload reader blocked")
	}
	oc.mu.Lock()
	receive := len(oc.streams)
	oc.mu.Unlock()
	oc.out.mu.Lock()
	send := len(oc.out.stream)
	oc.out.mu.Unlock()
	oc.inbound.mu.Lock()
	inbound := len(oc.inbound.stream)
	oc.inbound.mu.Unlock()
	if receive != 0 || send != 0 || inbound != 0 {
		t.Fatalf("aborted stream retained: receive=%d send=%d inbound=%d", receive, send, inbound)
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/next", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = oc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(body) != "next" {
		t.Fatalf("next=%q err=%v", body, err)
	}
}

type interruptedUploadBody struct {
	closed  chan struct{}
	once    sync.Once
	payload bool
}

func (b *interruptedUploadBody) Read(p []byte) (int, error) {
	if b.payload {
		b.payload = false
		return copy(p, "upload"), nil
	}
	<-b.closed
	return 0, io.ErrClosedPipe
}
func (b *interruptedUploadBody) Close() error { b.once.Do(func() { close(b.closed) }); return nil }

func TestOriginNoErrorResetPreservesCompletedResponseDuringUpload(t *testing.T) {
	for _, blockedWindow := range []bool{false, true} {
		t.Run(fmt.Sprint(blockedWindow), func(t *testing.T) {
			var frame, output bytes.Buffer
			if err := http2.NewFramer(&frame, nil).WriteRSTStream(1, http2.ErrCodeNo); err != nil {
				t.Fatal(err)
			}
			tail, tailWriter := io.Pipe()
			defer func() { _ = tail.Close(); _ = tailWriter.Close() }()
			oc := &OriginConn{fr: http2.NewFramer(&output, io.MultiReader(&frame, tail)), out: newOutFlow(), inbound: newInFlow(), streams: make(map[uint32]*originStream), pushes: make(map[uint32]*pushStream)}
			var writeMu sync.Mutex
			oc.write = func(fn func() error) error { writeMu.Lock(); defer writeMu.Unlock(); return fn() }
			upload := &interruptedUploadBody{closed: make(chan struct{}), payload: blockedWindow}
			st := &originStream{id: 1, body: newBodyBuf(nil), requestBody: upload, hdr: make(chan []hpack.HeaderField, 1), fail: make(chan error, 1)}
			st.gotResp.Store(true)
			st.closed.Store(true)
			_, _ = st.body.Write([]byte("complete"))
			_ = st.body.Close()
			st.hdr <- []hpack.HeaderField{{Name: ":status", Value: "200"}}
			oc.streams[1] = st
			oc.out.open(1)
			oc.inbound.open(1)
			if blockedWindow {
				oc.out.mu.Lock()
				oc.out.stream[1] = 0
				oc.out.mu.Unlock()
			}
			uploadDone := make(chan struct{})
			go func() { oc.writeRequestBody(1, upload); close(uploadDone) }()
			go oc.readLoop()
			select {
			case <-upload.closed:
			case <-time.After(time.Second):
				t.Fatal("NO_ERROR did not close unused upload")
			}
			select {
			case <-uploadDone:
			case <-time.After(time.Second):
				t.Fatal("unused upload writer remains blocked")
			}
			select {
			case err := <-st.fail:
				t.Fatalf("completed response failed with unused upload: %v", err)
			default:
			}
			select {
			case fields := <-st.hdr:
				if fields[0].Value != "200" {
					t.Fatalf("headers=%v", fields)
				}
			default:
				t.Fatal("completed response headers lost")
			}
			body, err := io.ReadAll(st.body)
			if err != nil || string(body) != "complete" {
				t.Fatalf("completed body=%q err=%v", body, err)
			}
			oc.mu.Lock()
			retained := oc.streams[1] == st
			oc.mu.Unlock()
			if !retained {
				t.Fatal("completed response retired before consumer")
			}
			st.responseDone.Store(true)
			oc.retire(st)
			oc.mu.Lock()
			n := len(oc.streams)
			oc.mu.Unlock()
			if n != 0 {
				t.Fatal("consumed response stream retained")
			}
		})
	}
}

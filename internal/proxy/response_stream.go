package proxy

import (
	"context"
	"io"
	"net/http"
	"sync"
)

// responseStream hands headers to the codec immediately. Its pipe applies
// backpressure instead of retaining the origin's entire response in memory.
type responseStream struct {
	ready  chan struct{}
	once   sync.Once
	reader *io.PipeReader
	writer *boundedResponseWriter
	resp   *http.Response
	err    error
	cancel context.CancelFunc
}

func newResponseStream(ctx context.Context) (*responseStream, context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	r, w := io.Pipe()
	queue := make(chan responseChunk, 2)
	writer := &boundedResponseWriter{ctx: ctx, queue: queue}
	go func() {
		for {
			select {
			case <-ctx.Done():
				_ = w.CloseWithError(ctx.Err())
				return
			case chunk := <-queue:
				if chunk.done {
					_ = w.CloseWithError(chunk.err)
					return
				}
				if _, err := w.Write(chunk.data); err != nil {
					return
				}
			}
		}
	}()
	p := &responseStream{ready: make(chan struct{}), reader: r, writer: writer, cancel: cancel}
	go func() { <-ctx.Done(); _ = r.CloseWithError(ctx.Err()); _ = w.CloseWithError(ctx.Err()) }()
	return p, ctx
}

func (p *responseStream) publish(resp *http.Response) *http.Response {
	out := new(http.Response)
	*out = *resp
	out.Header = resp.Header.Clone()
	out.Trailer = make(http.Header)
	out.Body = &streamResponseBody{ReadCloser: p.reader, cancel: p.cancel}
	p.resp = out
	p.once.Do(func() { close(p.ready) })
	return out
}

func (p *responseStream) write(resp *http.Response) error {
	out := p.publish(resp)
	if resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
		if _, err := io.Copy(p.writer, resp.Body); err != nil {
			return err
		}
	}
	for k, vs := range resp.Trailer {
		out.Trailer[k] = append([]string(nil), vs...)
	}
	return nil
}

func (p *responseStream) finish(err error) {
	p.err = err
	p.once.Do(func() { close(p.ready) })
	_ = p.writer.CloseWithError(err)
}

func (p *responseStream) response() (*http.Response, error) {
	<-p.ready
	if p.resp == nil {
		p.cancel()
		return nil, p.err
	}
	return p.resp, nil
}

type streamResponseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *streamResponseBody) Close() error { b.cancel(); return b.ReadCloser.Close() }

// originResponseBody holds D44 ownership through actual origin consumption.
// A bounded mutation can close it before a response breakpoint pauses.
type originResponseBody struct {
	io.ReadCloser
	once     sync.Once
	release  func()
	closeErr error
}

func (b *originResponseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		_ = b.Close()
	}
	return n, err
}
func (b *originResponseBody) Close() error {
	b.once.Do(func() { b.closeErr = b.ReadCloser.Close(); b.release() })
	return b.closeErr
}

type responseChunk struct {
	data []byte
	err  error
	done bool
}
type boundedResponseWriter struct {
	ctx   context.Context
	queue chan responseChunk
}

func (w *boundedResponseWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 16<<10 {
			n = 16 << 10
		}
		chunk := append([]byte(nil), p[:n]...)
		select {
		case <-w.ctx.Done():
			return total, w.ctx.Err()
		case w.queue <- responseChunk{data: chunk}:
			total += n
			p = p[n:]
		}
	}
	return total, nil
}
func (w *boundedResponseWriter) CloseWithError(err error) error {
	select {
	case <-w.ctx.Done():
		return w.ctx.Err()
	case w.queue <- responseChunk{done: true, err: err}:
		return nil
	}
}

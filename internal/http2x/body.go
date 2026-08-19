package http2x

import (
	"io"
	"sync"
)

// bodyBuf is a request-body pipe whose Write never blocks the Framer loop.
// WINDOW_UPDATE is issued after the handler Read consumes bytes.
type bodyBuf struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	closed bool
	err    error
	onRead func(n int)
}

func newBodyBuf(onRead func(n int)) *bodyBuf {
	b := &bodyBuf{onRead: onRead}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *bodyBuf) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	b.buf = append(b.buf, p...)
	b.cond.Broadcast()
	return len(p), nil
}

func (b *bodyBuf) Read(p []byte) (int, error) {
	b.mu.Lock()
	for len(b.buf) == 0 && !b.closed {
		b.cond.Wait()
	}
	if len(b.buf) == 0 {
		err := b.err
		if err == nil {
			err = io.EOF
		}
		b.mu.Unlock()
		return 0, err
	}
	n := copy(p, b.buf)
	b.buf = append([]byte(nil), b.buf[n:]...)
	onRead := b.onRead
	b.mu.Unlock()
	if n > 0 && onRead != nil {
		onRead(n)
	}
	return n, nil
}

func (b *bodyBuf) Close() error {
	return b.CloseWithError(io.EOF)
}

func (b *bodyBuf) CloseWithError(err error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	if err == nil {
		err = io.EOF
	}
	b.err = err
	b.closed = true
	b.cond.Broadcast()
	return nil
}

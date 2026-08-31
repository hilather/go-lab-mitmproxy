package http2x

import (
	"io"
	"os"
	"sync"
	"time"
)

// bodyBuf is a request-body pipe whose Write never blocks the Framer loop.
// WINDOW_UPDATE is issued after the handler Read consumes bytes.
type bodyBuf struct {
	mu       sync.Mutex
	cond     *sync.Cond
	buf      []byte
	closed   bool
	err      error
	onRead   func(n int)
	deadline time.Time
	timer    *time.Timer
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

func (b *bodyBuf) SetReadDeadline(t time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deadline = t
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	if t.IsZero() {
		b.cond.Broadcast()
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		b.cond.Broadcast()
		return nil
	}
	b.timer = time.AfterFunc(d, func() {
		b.mu.Lock()
		b.cond.Broadcast()
		b.mu.Unlock()
	})
	return nil
}

func (b *bodyBuf) deadlineExceeded() bool {
	return !b.deadline.IsZero() && !time.Now().Before(b.deadline)
}

func (b *bodyBuf) Read(p []byte) (int, error) {
	b.mu.Lock()
	for len(b.buf) == 0 && !b.closed {
		if b.deadlineExceeded() {
			b.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		b.cond.Wait()
	}
	if len(b.buf) == 0 {
		if b.deadlineExceeded() && (b.err == nil || b.err == io.EOF) {
			b.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
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

func (b *bodyBuf) Closed() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
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
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	b.cond.Broadcast()
	return nil
}

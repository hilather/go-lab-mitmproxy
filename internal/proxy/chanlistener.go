package proxy

import (
	"net"
	"sync"
)

// chanListener is an in-process net.Listener. Accept never peeks.
// Push hands a ready conn to http.Server; Close unblocks Accept with
// net.ErrClosed and closes queued conns (D42).
type chanListener struct {
	addr   net.Addr
	mu     sync.Mutex
	cond   *sync.Cond
	q      []net.Conn
	closed bool
}

func newChanListener(addr net.Addr) *chanListener {
	l := &chanListener{addr: addr}
	l.cond = sync.NewCond(&l.mu)
	return l
}

var _ net.Listener = (*chanListener)(nil)

func (l *chanListener) Addr() net.Addr {
	if l == nil {
		return nil
	}
	return l.addr
}

func (l *chanListener) Accept() (net.Conn, error) {
	if l == nil {
		return nil, net.ErrClosed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for len(l.q) == 0 && !l.closed {
		l.cond.Wait()
	}
	if l.closed {
		return nil, net.ErrClosed
	}
	c := l.q[0]
	l.q[0] = nil
	l.q = l.q[1:]
	return c, nil
}

// Push queues c for Accept. After Close, c is closed and not queued.
func (l *chanListener) Push(c net.Conn) {
	if l == nil || c == nil {
		if c != nil {
			_ = c.Close()
		}
		return
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = c.Close()
		return
	}
	l.q = append(l.q, c)
	l.cond.Signal()
	l.mu.Unlock()
}

func (l *chanListener) Close() error {
	if l == nil {
		return net.ErrClosed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return net.ErrClosed
	}
	l.closed = true
	for i, c := range l.q {
		if c != nil {
			_ = c.Close()
		}
		l.q[i] = nil
	}
	l.q = nil
	l.cond.Broadcast()
	return nil
}

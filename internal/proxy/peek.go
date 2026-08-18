package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
)

var errSOCKS = errors.New("socks")

// peekListener returns each accepted conn immediately. SOCKS is detected on
// the first Read (http.Server's serve goroutine), so a silent peer cannot
// stall the accept loop.
type peekListener struct {
	net.Listener
	reject func()
}

func (l *peekListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &peekConn{Conn: c, reject: l.reject}, nil
}

type peekConn struct {
	net.Conn
	buf    []byte
	reject func()
	once   sync.Once
	err    error
}

func (c *peekConn) peek(n int) ([]byte, error) {
	if len(c.buf) >= n {
		return c.buf[:n], nil
	}
	tmp := make([]byte, n-len(c.buf))
	nr, err := io.ReadFull(c.Conn, tmp)
	if nr > 0 {
		c.buf = append(c.buf, tmp[:nr]...)
	}
	if len(c.buf) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
	return c.buf, nil
}

func (c *peekConn) checkSOCKS() {
	b, err := c.peek(1)
	if err != nil {
		c.err = err
		_ = c.Conn.Close()
		return
	}
	if len(b) > 0 && (b[0] == 0x04 || b[0] == 0x05) {
		_ = c.Conn.Close()
		if c.reject != nil {
			c.reject()
		}
		c.err = errSOCKS
	}
}

func (c *peekConn) Read(p []byte) (int, error) {
	c.once.Do(c.checkSOCKS)
	if c.err != nil {
		return 0, c.err
	}
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

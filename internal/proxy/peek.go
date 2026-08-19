package proxy

import (
	"io"
	"net"
	"time"
)

// peekedConn replays buf on Read, then the underlying Conn.
type peekedConn struct {
	net.Conn
	buf []byte
}

func (c *peekedConn) Read(p []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *peekedConn) CloseWrite() error {
	if c == nil {
		return net.ErrClosed
	}
	type closer interface {
		CloseWrite() error
	}
	if cw, ok := c.Conn.(closer); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// peekReplay reads n bytes from c. The returned conn's Read replays those
// bytes before the remainder of c.
func peekReplay(c net.Conn, n int) (net.Conn, []byte, error) {
	if n <= 0 {
		return c, nil, nil
	}
	if c == nil {
		return nil, nil, net.ErrClosed
	}
	buf := make([]byte, n)
	nr, err := io.ReadFull(c, buf)
	if nr == 0 {
		if err != nil {
			return c, nil, err
		}
		return c, nil, io.EOF
	}
	b := buf[:nr]
	return &peekedConn{Conn: c, buf: append([]byte(nil), b...)}, b, err
}

func (s *Server) dispatchConn(c net.Conn, httpLn *chanListener) {
	defer s.dispatchWG.Done()
	if c == nil {
		return
	}
	spec := withSpecDefaults(s.liveSpec())
	ht := spec.Proxy.Admission.HeaderTimeout
	if ht <= 0 {
		ht = defaultHeaderTimeout
	}
	_ = c.SetReadDeadline(time.Now().Add(ht))
	pc, b, err := peekReplay(c, 1)
	_ = c.SetReadDeadline(time.Time{})
	s.untrackDispatch(c)
	if err != nil || len(b) == 0 {
		_ = c.Close()
		return
	}
	if b[0] == 0x04 || b[0] == 0x05 {
		s.closeSOCKS(pc)
		return
	}
	if httpLn == nil {
		_ = c.Close()
		return
	}
	httpLn.Push(pc)
}

func (s *Server) closeSOCKS(c net.Conn) {
	if c != nil {
		_ = c.Close()
	}
	s.metrics.reject("socks")
}

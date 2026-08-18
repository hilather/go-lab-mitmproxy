package proxy

import (
	"io"
	"net"
	"time"
)

// peekListener wraps Accept: first byte 0x04/0x05 is SOCKS and is closed.
type peekListener struct {
	net.Listener
	timeout time.Duration
	reject  func()
}

func (l *peekListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		pc := &peekConn{Conn: c}
		deadline := l.timeout
		if deadline <= 0 {
			deadline = 10 * time.Second
		}
		_ = c.SetReadDeadline(time.Now().Add(deadline))
		b, err := pc.peek(1)
		_ = c.SetReadDeadline(time.Time{})
		if err != nil {
			_ = c.Close()
			if err == io.EOF {
				continue
			}
			continue
		}
		if len(b) > 0 && (b[0] == 0x04 || b[0] == 0x05) {
			_ = c.Close()
			if l.reject != nil {
				l.reject()
			}
			continue
		}
		return pc, nil
	}
}

type peekConn struct {
	net.Conn
	buf []byte
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

func (c *peekConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

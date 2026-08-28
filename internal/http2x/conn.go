package http2x

import (
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// framedStreamConn is one HTTP/2 stream as a net.Conn. Read is DATA into
// body; Write honors the send window via outFlow.take.
// Deadlines apply to this stream only and must not touch the parent TLS conn.
type framedStreamConn struct {
	parent net.Conn
	id     uint32
	body   io.ReadCloser
	out    *outFlow
	fr     *http2.Framer
	write  func(func() error) error

	mu            sync.Mutex
	writeClosed   bool
	wrote         bool
	writeDeadline time.Time
}

func (c *framedStreamConn) Read(p []byte) (int, error) {
	if c.body == nil {
		return 0, io.EOF
	}
	return c.body.Read(p)
}

func (c *framedStreamConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := 0
	for n < len(p) {
		c.mu.Lock()
		closed := c.writeClosed
		dl := c.writeDeadline
		c.mu.Unlock()
		if closed {
			return n, io.ErrClosedPipe
		}
		take, err := c.out.takeDeadline(c.id, len(p)-n, dl)
		if err != nil {
			return n, err
		}
		payload := append([]byte(nil), p[n:n+take]...)
		if werr := c.write(func() error {
			return c.fr.WriteData(c.id, false, payload)
		}); werr != nil {
			return n, werr
		}
		c.mu.Lock()
		c.wrote = true
		c.mu.Unlock()
		n += take
	}
	return n, nil
}

// ResetCancel writes RST_STREAM CANCEL on a framed stream, including after
// DATA has already been written (AfterAck intercept). Close after write is
// DATA endStream and is not silent rst.
func ResetCancel(c net.Conn) bool {
	f, ok := c.(*framedStreamConn)
	if !ok || f == nil {
		return false
	}
	f.mu.Lock()
	f.writeClosed = true
	f.mu.Unlock()
	if f.body != nil {
		_ = f.body.Close()
	}
	_ = f.write(func() error { return f.fr.WriteRSTStream(f.id, http2.ErrCodeCancel) })
	return true
}

func (c *framedStreamConn) Close() error {
	c.mu.Lock()
	wrote := c.wrote
	c.mu.Unlock()
	if !wrote {
		// Handshake fail after 2xx: RST the stream, do not DATA-tunnel (D20).
		_ = c.write(func() error { return c.fr.WriteRSTStream(c.id, http2.ErrCodeConnect) })
		if c.body != nil {
			_ = c.body.Close()
		}
		return nil
	}
	_ = c.CloseWrite()
	if c.body != nil {
		_ = c.body.Close()
	}
	return nil
}

func (c *framedStreamConn) CloseWrite() error {
	c.mu.Lock()
	if c.writeClosed {
		c.mu.Unlock()
		return nil
	}
	c.writeClosed = true
	c.mu.Unlock()
	return c.write(func() error {
		return c.fr.WriteData(c.id, true, nil)
	})
}

func (c *framedStreamConn) LocalAddr() net.Addr {
	if c.parent != nil {
		return c.parent.LocalAddr()
	}
	return streamAddr{}
}

func (c *framedStreamConn) RemoteAddr() net.Addr {
	if c.parent != nil {
		return c.parent.RemoteAddr()
	}
	return streamAddr{}
}

func (c *framedStreamConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *framedStreamConn) SetReadDeadline(t time.Time) error {
	if b, ok := c.body.(*bodyBuf); ok {
		return b.SetReadDeadline(t)
	}
	return nil
}

func (c *framedStreamConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	if c.out != nil {
		c.out.mu.Lock()
		c.out.cond.Broadcast()
		c.out.mu.Unlock()
	}
	return nil
}

type streamAddr struct{}

func (streamAddr) Network() string { return "tcp" }
func (streamAddr) String() string  { return "h2-stream" }

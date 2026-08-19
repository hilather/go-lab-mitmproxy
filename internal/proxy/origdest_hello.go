package proxy

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

type clientHello struct {
	ServerName string
	ALPN       []string
}

type recordingConn struct {
	net.Conn
	buf []byte
}

func (c *recordingConn) Read(p []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.buf = append(c.buf, p[:n]...)
	}
	return n, err
}

func (c *recordingConn) CloseWrite() error {
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

func readClientHello(c net.Conn, max int) (net.Conn, clientHello, error) {
	if c == nil {
		return nil, clientHello{}, net.ErrClosed
	}
	if max <= 0 {
		max = 16 << 10
	}
	rec := &recordingConn{Conn: c}
	hello, err := parseClientHelloRecord(rec, max)
	if err != nil {
		return c, clientHello{}, err
	}
	return &peekedConn{Conn: rec.Conn, buf: append([]byte(nil), rec.buf...)}, hello, nil
}

func parseClientHelloRecord(r io.Reader, max int) (clientHello, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return clientHello{}, err
	}
	if hdr[0] != 0x16 {
		return clientHello{}, errors.New("proxy: not a TLS handshake record")
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n <= 0 || n > max {
		return clientHello{}, errors.New("proxy: ClientHello record too large")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return clientHello{}, err
	}
	return parseClientHelloHandshake(payload)
}

func parseClientHelloHandshake(b []byte) (clientHello, error) {
	if len(b) < 4 {
		return clientHello{}, errors.New("proxy: truncated ClientHello")
	}
	if b[0] != 0x01 {
		return clientHello{}, errors.New("proxy: not a ClientHello")
	}
	hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	b = b[4:]
	if hsLen > len(b) {
		return clientHello{}, errors.New("proxy: truncated ClientHello")
	}
	b = b[:hsLen]
	if len(b) < 34 {
		return clientHello{}, errors.New("proxy: truncated ClientHello")
	}
	b = b[2+32:] // version + random
	if len(b) < 1 {
		return clientHello{}, errors.New("proxy: truncated ClientHello")
	}
	sid := int(b[0])
	b = b[1:]
	if sid > len(b) {
		return clientHello{}, errors.New("proxy: truncated ClientHello")
	}
	b = b[sid:]
	if len(b) < 2 {
		return clientHello{}, errors.New("proxy: truncated ClientHello")
	}
	cs := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if cs > len(b) || cs%2 != 0 {
		return clientHello{}, errors.New("proxy: truncated ClientHello")
	}
	b = b[cs:]
	if len(b) < 1 {
		return clientHello{}, errors.New("proxy: truncated ClientHello")
	}
	comp := int(b[0])
	b = b[1:]
	if comp > len(b) {
		return clientHello{}, errors.New("proxy: truncated ClientHello")
	}
	b = b[comp:]
	if len(b) == 0 {
		return clientHello{}, nil
	}
	if len(b) < 2 {
		return clientHello{}, errors.New("proxy: truncated ClientHello")
	}
	extLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if extLen > len(b) {
		return clientHello{}, errors.New("proxy: truncated ClientHello")
	}
	b = b[:extLen]
	var hello clientHello
	for len(b) >= 4 {
		typ := binary.BigEndian.Uint16(b[:2])
		n := int(binary.BigEndian.Uint16(b[2:4]))
		b = b[4:]
		if n > len(b) {
			return clientHello{}, errors.New("proxy: truncated ClientHello")
		}
		body := b[:n]
		b = b[n:]
		switch typ {
		case 0:
			hello.ServerName = parseSNI(body)
		case 16:
			hello.ALPN = parseALPN(body)
		}
	}
	return hello, nil
}

func parseSNI(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if n > len(b) {
		return ""
	}
	b = b[:n]
	for len(b) >= 3 {
		nameType := b[0]
		ln := int(binary.BigEndian.Uint16(b[1:3]))
		b = b[3:]
		if ln > len(b) {
			return ""
		}
		if nameType == 0 {
			return string(b[:ln])
		}
		b = b[ln:]
	}
	return ""
}

func parseALPN(b []byte) []string {
	if len(b) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if n > len(b) {
		return nil
	}
	b = b[:n]
	var out []string
	for len(b) >= 1 {
		ln := int(b[0])
		b = b[1:]
		if ln > len(b) {
			return out
		}
		out = append(out, string(b[:ln]))
		b = b[ln:]
	}
	return out
}

package proxytest

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client is a raw HTTP/1.1 peer used by proxy transcripts and protocol tests.
type Client struct {
	Conn net.Conn
	br   *bufio.Reader
}

// Dial connects to addr. Allowed: this package is internal/proxytest.
func Dial(addr string) (*Client, error) {
	return DialTimeout(addr, 5*time.Second)
}

// DialTimeout connects with a deadline.
func DialTimeout(addr string, d time.Duration) (*Client, error) {
	conn, err := net.DialTimeout("tcp", addr, d)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return &Client{Conn: conn, br: bufio.NewReader(conn)}, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.Close()
}

// WriteRaw writes p as-is.
func (c *Client) WriteRaw(p []byte) error {
	if c == nil || c.Conn == nil {
		return fmt.Errorf("proxytest: nil conn")
	}
	_ = c.Conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err := c.Conn.Write(p)
	return err
}

// WriteLine writes s plus CRLF. An empty s writes a blank line.
func (c *Client) WriteLine(s string) error {
	return c.WriteRaw([]byte(s + "\r\n"))
}

// WriteRequest writes lines (without CRLF) followed by a blank line.
func (c *Client) WriteRequest(lines ...string) error {
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	return c.WriteRaw([]byte(b.String()))
}

// ReadLine reads one CRLF-delimited line without the terminator.
func (c *Client) ReadLine() (string, error) {
	if c == nil || c.br == nil {
		return "", fmt.Errorf("proxytest: nil conn")
	}
	_ = c.Conn.SetDeadline(time.Now().Add(10 * time.Second))
	s, err := c.br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

// ReadResponse reads one HTTP/1.x response (headers + body if Content-Length).
func (c *Client) ReadResponse() (*http.Response, error) {
	if c == nil || c.br == nil {
		return nil, fmt.Errorf("proxytest: nil conn")
	}
	_ = c.Conn.SetDeadline(time.Now().Add(10 * time.Second))
	return http.ReadResponse(c.br, nil)
}

// ReadN reads n bytes from the connection (after any buffered data).
func (c *Client) ReadN(n int) ([]byte, error) {
	if c == nil || c.br == nil {
		return nil, fmt.Errorf("proxytest: nil conn")
	}
	_ = c.Conn.SetDeadline(time.Now().Add(10 * time.Second))
	p := make([]byte, n)
	_, err := io.ReadFull(c.br, p)
	return p, err
}

// Buffered reports unread buffered bytes.
func (c *Client) Buffered() int {
	if c == nil || c.br == nil {
		return 0
	}
	return c.br.Buffered()
}

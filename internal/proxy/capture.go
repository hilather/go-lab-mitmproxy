package proxy

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// Sink is a best-effort flow capture. Insert must not fail the client hop.
// AdaptStore wraps store.Store; NewNull remains the test/fallback sink.
type Sink interface {
	Insert(ctx context.Context, f *model.Flow)
}

// Null discards captured flows after optionally retaining the last N for tests.
type Null struct {
	mu    sync.Mutex
	seq   atomic.Uint64
	last  []*model.Flow
	keep  int
	count int
}

// NewNull returns a capture-only sink. keep=0 retains nothing.
func NewNull() *Null {
	return &Null{keep: 32}
}

// Insert records a completed or metadata-only flow.
func (n *Null) Insert(_ context.Context, f *model.Flow) {
	if n == nil || f == nil {
		return
	}
	id := n.seq.Add(1)
	if f.ID == "" {
		f.ID = formatNullID(id)
	}
	if f.CompletedAt.IsZero() {
		f.CompletedAt = time.Now().UTC()
	}
	n.mu.Lock()
	n.count++
	if n.keep > 0 {
		n.last = append(n.last, f)
		if len(n.last) > n.keep {
			n.last = n.last[len(n.last)-n.keep:]
		}
	}
	n.mu.Unlock()
}

// Last returns a snapshot of retained flows (oldest first).
func (n *Null) Last() []*model.Flow {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]*model.Flow, len(n.last))
	copy(out, n.last)
	return out
}

// Count is the number of Insert calls.
func (n *Null) Count() int {
	if n == nil {
		return 0
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.count
}

func formatNullID(n uint64) string {
	return "null-" + itoa(n)
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

const streamSlack = 64 << 10

type cappedWriter struct {
	buf       []byte
	max       int
	truncated bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.max <= 0 {
		c.max = int(1 << 20)
	}
	remain := c.max - len(c.buf)
	if remain > 0 {
		if len(p) > remain {
			c.buf = append(c.buf, p[:remain]...)
			c.truncated = true
		} else {
			c.buf = append(c.buf, p...)
		}
	} else if len(p) > 0 {
		c.truncated = true
	}
	return len(p), nil
}

func teeBody(r io.ReadCloser, max int64) (io.ReadCloser, *cappedWriter) {
	capw := &cappedWriter{max: int(max)}
	if r == nil {
		return nil, capw
	}
	return &teeCloser{Reader: io.TeeReader(r, capw), c: r}, capw
}

type teeCloser struct {
	io.Reader
	c io.Closer
}

func (t *teeCloser) Close() error {
	if t.c != nil {
		return t.c.Close()
	}
	return nil
}

func headersFrom(h map[string][]string) []model.Header {
	if len(h) == 0 {
		return nil
	}
	out := make([]model.Header, 0, len(h))
	for name, vs := range h {
		for _, v := range vs {
			out = append(out, model.Header{Name: name, Value: v})
		}
	}
	return out
}

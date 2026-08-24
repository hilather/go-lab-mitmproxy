package http2x

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/http2"
)

// NewOriginTransport binds an HTTP/2 client to an already-dialed origin conn.
// DialTLS stays nil. DialTLSContext refuses a second open instead of tls.Dial.
// Inner streams multiplex on that one TCP (D64). Client SETTINGS EnablePush=0;
// PUSH_PROMISE is not captured on this path.
func NewOriginTransport(up net.Conn) (*http2.Transport, error) {
	if up == nil {
		return nil, ErrRefuseRedial
	}
	tr := &http2.Transport{
		DisableCompression: true,
		AllowHTTP:          true, // already-dialed conn
		DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
			return nil, ErrRefuseRedial
		},
	}
	cc, err := tr.NewClientConn(up)
	if err != nil {
		return nil, err
	}
	tr.ConnPool = &pinnedPool{cc: cc}
	return tr, nil
}

// pinnedPool returns one ClientConn. It never Dials.
type pinnedPool struct {
	mu sync.Mutex
	cc *http2.ClientConn
}

func (p *pinnedPool) GetClientConn(_ *http.Request, _ string) (*http2.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cc == nil {
		return nil, ErrRefuseRedial
	}
	st := p.cc.State()
	if st.Closed || st.Closing {
		p.cc = nil
		return nil, ErrRefuseRedial
	}
	if !p.cc.ReserveNewRequest() {
		return nil, ErrRefuseRedial
	}
	return p.cc, nil
}

func (p *pinnedPool) MarkDead(cc *http2.ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cc == cc {
		p.cc = nil
	}
}

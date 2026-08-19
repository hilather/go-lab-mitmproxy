package http2x

import (
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/http2"
)

// NewOriginTransport binds an HTTP/2 client to an already-dialed origin conn.
// DialTLS / DialTLSContext stay nil. A second open errors ErrRefuseRedial.
func NewOriginTransport(up net.Conn) (*http2.Transport, error) {
	if up == nil {
		return nil, ErrRefuseRedial
	}
	tr := &http2.Transport{
		DisableCompression: true,
		AllowHTTP:          true, // already-dialed conn; never tls.Dial
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

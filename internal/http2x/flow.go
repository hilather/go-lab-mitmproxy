package http2x

import (
	"io"
	"sync"
)

const defaultHTTP2Window = 65535

// outFlow tracks send windows so WriteData honors peer SETTINGS / WINDOW_UPDATE.
type outFlow struct {
	mu         sync.Mutex
	cond       *sync.Cond
	conn       int32
	stream     map[uint32]int32
	initStream int32
	maxFrame   uint32
	closed     bool
}

func newOutFlow() *outFlow {
	f := &outFlow{
		conn:       defaultHTTP2Window,
		stream:     make(map[uint32]int32),
		initStream: defaultHTTP2Window,
		maxFrame:   maxFramePayload,
	}
	f.cond = sync.NewCond(&f.mu)
	return f
}

func (f *outFlow) open(id uint32) {
	f.mu.Lock()
	if _, ok := f.stream[id]; !ok {
		f.stream[id] = f.initStream
	}
	f.mu.Unlock()
}

func (f *outFlow) forget(id uint32) {
	f.mu.Lock()
	delete(f.stream, id)
	f.cond.Broadcast()
	f.mu.Unlock()
}

func (f *outFlow) add(streamID uint32, n int32) {
	if n == 0 {
		return
	}
	f.mu.Lock()
	if streamID == 0 {
		f.conn += n
	} else {
		if _, ok := f.stream[streamID]; !ok {
			f.stream[streamID] = f.initStream
		}
		f.stream[streamID] += n
	}
	f.cond.Broadcast()
	f.mu.Unlock()
}

func (f *outFlow) applyInitialWindow(v uint32) {
	f.mu.Lock()
	next := int32(v)
	delta := next - f.initStream
	f.initStream = next
	if delta != 0 {
		for id, cur := range f.stream {
			f.stream[id] = cur + delta
		}
	}
	f.cond.Broadcast()
	f.mu.Unlock()
}

func (f *outFlow) setMaxFrame(v uint32) {
	if v < 16384 {
		v = 16384
	}
	if v > 1<<24-1 {
		v = 1<<24 - 1
	}
	f.mu.Lock()
	f.maxFrame = v
	f.cond.Broadcast()
	f.mu.Unlock()
}

func (f *outFlow) close() {
	f.mu.Lock()
	f.closed = true
	f.cond.Broadcast()
	f.mu.Unlock()
}

func (f *outFlow) take(id uint32, want int) (int, error) {
	if want <= 0 {
		return 0, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for {
		if f.closed {
			return 0, io.ErrClosedPipe
		}
		s, ok := f.stream[id]
		if !ok {
			s = f.initStream
			f.stream[id] = s
		}
		avail := f.conn
		if s < avail {
			avail = s
		}
		if f.maxFrame > 0 && int32(f.maxFrame) < avail {
			avail = int32(f.maxFrame)
		}
		if avail > 0 {
			if int(avail) > want {
				avail = int32(want)
			}
			f.conn -= avail
			f.stream[id] -= avail
			return int(avail), nil
		}
		f.cond.Wait()
	}
}

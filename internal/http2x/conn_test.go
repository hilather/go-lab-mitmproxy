package http2x

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

type deadlineProbe struct {
	net.Conn
	n int
}

func (d *deadlineProbe) SetDeadline(time.Time) error {
	d.n++
	return nil
}

func (d *deadlineProbe) SetReadDeadline(time.Time) error {
	d.n++
	return nil
}

func (d *deadlineProbe) SetWriteDeadline(time.Time) error {
	d.n++
	return nil
}

func TestFramedStreamConnReadDeadlineDoesNotTouchParent(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	probe := &deadlineProbe{Conn: a}
	body := newBodyBuf(nil)
	c := &framedStreamConn{parent: probe, id: 1, body: body, out: newOutFlow()}
	if err := c.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if probe.n != 0 {
		t.Fatalf("parent deadline set %d times", probe.n)
	}
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 8))
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stream read deadline did not fire")
	}
	if probe.n != 0 {
		t.Fatalf("parent deadline set during wait (%d)", probe.n)
	}
}

func TestOutFlowTakeAfterForgetDoesNotSpendConnWindow(t *testing.T) {
	f := newOutFlow()
	f.open(1)
	f.mu.Lock()
	before := f.conn
	f.mu.Unlock()
	f.forget(1)
	n, err := f.take(1, 100)
	if err == nil || n != 0 {
		t.Fatalf("take after forget n=%d err=%v", n, err)
	}
	f.mu.Lock()
	after := f.conn
	_, resurrected := f.stream[1]
	f.mu.Unlock()
	if after != before {
		t.Fatalf("conn window %d → %d after take on forgotten stream", before, after)
	}
	if resurrected {
		t.Fatal("take must not re-open a forgotten stream")
	}
}

func TestOutFlowForgetUnblocksTakeWithoutSpendingConnWindow(t *testing.T) {
	f := newOutFlow()
	f.open(1)
	f.mu.Lock()
	f.stream[1] = 0
	before := f.conn
	f.mu.Unlock()
	done := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := f.take(1, 10)
		done <- struct {
			n   int
			err error
		}{n, err}
	}()
	select {
	case <-done:
		t.Fatal("take did not block on empty window")
	case <-time.After(30 * time.Millisecond):
	}
	f.forget(1)
	select {
	case got := <-done:
		if got.err == nil || got.n != 0 {
			t.Fatalf("blocked take after forget n=%d err=%v", got.n, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("forget did not unblock take")
	}
	f.mu.Lock()
	after := f.conn
	_, resurrected := f.stream[1]
	f.mu.Unlock()
	if after != before {
		t.Fatalf("conn window %d → %d", before, after)
	}
	if resurrected {
		t.Fatal("forget+take must not re-open the stream")
	}
}

func TestOutFlowAddAfterForgetDoesNotResurrect(t *testing.T) {
	f := newOutFlow()
	f.open(1)
	f.forget(1)
	f.add(1, 100)
	n, err := f.take(1, 10)
	if err == nil || n != 0 {
		t.Fatalf("WINDOW_UPDATE after forget resurrected take n=%d err=%v", n, err)
	}
}

func TestOutFlowTakeWaitsForWindow(t *testing.T) {
	f := newOutFlow()
	f.open(1)
	f.mu.Lock()
	f.stream[1] = 0
	f.mu.Unlock()
	done := make(chan int, 1)
	go func() {
		n, err := f.take(1, 10)
		if err != nil {
			done <- -1
			return
		}
		done <- n
	}()
	select {
	case <-done:
		t.Fatal("take did not block on empty window")
	case <-time.After(30 * time.Millisecond):
	}
	f.add(1, 10)
	select {
	case n := <-done:
		if n != 10 {
			t.Fatalf("take %d", n)
		}
	case <-time.After(time.Second):
		t.Fatal("take did not resume after WINDOW_UPDATE")
	}
}

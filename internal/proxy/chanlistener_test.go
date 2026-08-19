package proxy

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestChanListenerAddr(t *testing.T) {
	want := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8888}
	ln := newChanListener(want)
	if got := ln.Addr(); got == nil || got.String() != want.String() {
		t.Fatalf("Addr=%v want %v", got, want)
	}
}

func TestChanListenerCloseUnblocksAccept(t *testing.T) {
	ln := newChanListener(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8888})
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept err %v want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept not unblocked by Close")
	}
	if err := ln.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close %v", err)
	}
}

func TestChanListenerCloseClosesQueued(t *testing.T) {
	ln := newChanListener(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	ln.Push(a)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	_ = b.SetDeadline(time.Now().Add(time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Fatal("queued conn still open after Close")
	}
}

func TestChanListenerPushAfterClose(t *testing.T) {
	ln := newChanListener(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	ln.Push(a)
	_ = b.SetDeadline(time.Now().Add(time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Fatal("Push after Close left conn open")
	}
}

func TestChanListenerAcceptReceivesPush(t *testing.T) {
	ln := newChanListener(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	t.Cleanup(func() { _ = ln.Close() })
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	got := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		got <- c
	}()
	ln.Push(a)
	select {
	case c := <-got:
		if c != a {
			t.Fatalf("Accept got %v want pushed conn", c)
		}
		_ = c.Close()
	case <-time.After(time.Second):
		t.Fatal("Accept did not receive Push")
	}
}

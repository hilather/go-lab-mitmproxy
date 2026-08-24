package http2x

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestBodyBufWriteDoesNotBlockOnUnread(t *testing.T) {
	b := newBodyBuf(nil)
	done := make(chan error, 1)
	go func() {
		_, err := b.Write([]byte("hello"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write blocked without a Read")
	}
	got := make([]byte, 8)
	n, err := b.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != "hello" {
		t.Fatalf("got %q", got[:n])
	}
	_ = b.Close()
	_, err = b.Read(got)
	if err != io.EOF {
		t.Fatalf("err=%v", err)
	}
}

func TestBodyBufReadDeadline(t *testing.T) {
	b := newBodyBuf(nil)
	if err := b.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := b.Read(make([]byte, 8))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !isTimeout(err) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read deadline did not fire")
	}
}

func isTimeout(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded)
}

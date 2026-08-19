package http2x

import (
	"io"
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

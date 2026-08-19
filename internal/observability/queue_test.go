package observability

import (
	"testing"
	"time"
)

func TestQueueDropDoesNotBlock(t *testing.T) {
	q := NewQueue[int](1)
	if !q.TrySend(1) {
		t.Fatal("first send")
	}
	done := make(chan struct{})
	go func() {
		if q.TrySend(2) {
			t.Error("second send should drop")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TrySend blocked")
	}
	if q.Dropped() != 1 {
		t.Fatalf("dropped=%d", q.Dropped())
	}
	if q.Len() != 1 || q.Cap() != 1 {
		t.Fatalf("len=%d cap=%d", q.Len(), q.Cap())
	}
}

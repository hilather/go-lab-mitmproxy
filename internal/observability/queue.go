package observability

import "sync/atomic"

// DefaultQueueSize is the in-process telemetry buffer. Overflow is dropped.
const DefaultQueueSize = 1024

// Queue is a bounded, non-blocking channel. TrySend never waits; a full
// queue increments Dropped and returns false so the proxy is not stalled.
type Queue[T any] struct {
	ch      chan T
	dropped atomic.Int64
}

// NewQueue returns a queue of size n. Non-positive n uses DefaultQueueSize.
func NewQueue[T any](n int) *Queue[T] {
	if n <= 0 {
		n = DefaultQueueSize
	}
	return &Queue[T]{ch: make(chan T, n)}
}

// TrySend enqueues v or drops it. It never blocks.
func (q *Queue[T]) TrySend(v T) bool {
	if q == nil {
		return false
	}
	select {
	case q.ch <- v:
		return true
	default:
		q.dropped.Add(1)
		return false
	}
}

// Recv is the receive side. Closing is not required for process lifetime.
func (q *Queue[T]) Recv() <-chan T {
	if q == nil {
		return nil
	}
	return q.ch
}

// Dropped is the number of rejected sends.
func (q *Queue[T]) Dropped() int64 {
	if q == nil {
		return 0
	}
	return q.dropped.Load()
}

// Cap is the configured buffer size.
func (q *Queue[T]) Cap() int {
	if q == nil {
		return 0
	}
	return cap(q.ch)
}

// Len is the current occupancy.
func (q *Queue[T]) Len() int {
	if q == nil {
		return 0
	}
	return len(q.ch)
}

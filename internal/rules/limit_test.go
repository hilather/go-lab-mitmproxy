package rules

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLimitReaderPassthroughZero(t *testing.T) {
	r := strings.NewReader("abc")
	if LimitReader(context.Background(), r, 0, nil) != r {
		t.Fatal("bps 0 must return r")
	}
	if LimitReader(context.Background(), r, 1, nil) != r {
		t.Fatal("below min must return r")
	}
	if LimitReader(context.Background(), nil, 8192, nil) != nil {
		t.Fatal("nil reader")
	}
}

func TestLimitReaderQuantumAndRemainder(t *testing.T) {
	const bps int64 = 8192
	payload := bytes.Repeat([]byte("x"), 32<<10)
	var mu sync.Mutex
	var slept time.Duration
	sleep := func(ctx context.Context, d time.Duration) bool {
		mu.Lock()
		slept += d
		mu.Unlock()
		return true
	}
	lr := LimitReader(context.Background(), bytes.NewReader(payload), bps, sleep)
	got, err := io.ReadAll(lr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("body len %d", len(got))
	}
	want := time.Duration(int64(len(payload)) * int64(time.Second) / bps)
	mu.Lock()
	gotSleep := slept
	mu.Unlock()
	if gotSleep < want {
		t.Fatalf("slept %s want >= %s", gotSleep, want)
	}
	// Remainder carry: 32KiB / 8KiB/s is exactly 4s.
	if gotSleep != 4*time.Second {
		t.Fatalf("slept %s want 4s (remainder carry)", gotSleep)
	}
}

func TestLimitReaderOneByteRemainderCarry(t *testing.T) {
	// 64MiB/s: a 1-byte Read is 15ns after remainder; without carry many
	// 1-byte Reads would floor to 0 and under-pace.
	const bps = MaxBytesPerSecond
	payload := bytes.Repeat([]byte("y"), 64)
	var slept time.Duration
	sleep := func(ctx context.Context, d time.Duration) bool {
		slept += d
		return true
	}
	lr := LimitReader(context.Background(), bytes.NewReader(payload), bps, sleep)
	buf := make([]byte, 1)
	var n int
	for {
		got, err := lr.Read(buf)
		n += got
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if n != len(payload) {
		t.Fatalf("n=%d", n)
	}
	want := time.Duration(int64(len(payload)) * int64(time.Second) / bps)
	if slept < want {
		t.Fatalf("slept %s want >= %s (remainder)", slept, want)
	}
}

func TestLimitReaderCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	payload := bytes.Repeat([]byte("z"), 2048)
	var calls int
	sleep := func(ctx context.Context, d time.Duration) bool {
		calls++
		return false
	}
	lr := LimitReader(ctx, bytes.NewReader(payload), 256, sleep)
	p := make([]byte, 1024)
	n, err := lr.Read(p)
	if n == 0 {
		t.Fatal("must return bytes already read")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if calls < 1 {
		t.Fatal("sleep must run")
	}
}

func TestLimitReaderCloseDelegates(t *testing.T) {
	var closed bool
	r := &closeRecorder{Reader: strings.NewReader("hi"), closed: &closed}
	lr := LimitReader(context.Background(), r, 1024, func(context.Context, time.Duration) bool { return true })
	c, ok := lr.(io.Closer)
	if !ok {
		t.Fatal("must implement Closer")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatal("Close must delegate")
	}
}

type closeRecorder struct {
	io.Reader
	closed *bool
}

func (c *closeRecorder) Close() error {
	*c.closed = true
	return nil
}

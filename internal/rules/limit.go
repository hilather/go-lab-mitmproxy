package rules

import (
	"context"
	"io"
	"time"
)

// LimitReader paces r at bps bytes/sec. bps is clamped; 0 returns r unchanged.
// Each Read copies at most min(1024, bps) bytes. After n>0 bytes it sleeps
// n * time.Second / bps plus a carried remainder so Σn over wall time
// converges to bps. sleep false (cancel / stop) returns n plus ctx.Err() or
// io.EOF. Close delegates when r is an io.Closer.
func LimitReader(ctx context.Context, r io.Reader, bps int64, sleep func(context.Context, time.Duration) bool) io.Reader {
	bps = ClampBytesPerSecond(bps)
	if bps == 0 || r == nil {
		return r
	}
	if sleep == nil {
		sleep = defaultSleep
	}
	quantum := int(bps)
	if quantum > 1024 {
		quantum = 1024
	}
	lr := &limitedReader{ctx: ctx, r: r, bps: bps, quantum: quantum, sleep: sleep}
	if c, ok := r.(io.Closer); ok {
		lr.c = c
	}
	return lr
}

func defaultSleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	if ctx == nil {
		ctx = context.Background()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

type limitedReader struct {
	ctx     context.Context
	r       io.Reader
	c       io.Closer
	bps     int64
	quantum int
	sleep   func(context.Context, time.Duration) bool
	rem     int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l == nil || l.r == nil {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > l.quantum {
		p = p[:l.quantum]
	}
	n, err := l.r.Read(p)
	if n > 0 {
		// n * Second / bps plus leftover nanoseconds so 1-byte Reads do not
		// floor to 0 at high legal rates (D75 remainder carry).
		acc := int64(n)*int64(time.Second) + l.rem
		d := time.Duration(acc / l.bps)
		l.rem = acc % l.bps
		if d > 0 && !l.sleep(l.ctx, d) {
			if l.ctx != nil && l.ctx.Err() != nil {
				return n, l.ctx.Err()
			}
			if err == nil {
				err = io.EOF
			}
			return n, err
		}
	}
	return n, err
}

func (l *limitedReader) Close() error {
	if l == nil || l.c == nil {
		return nil
	}
	return l.c.Close()
}

package observability

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Level is a structured log severity matching spec.observability.logLevel.
type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Record is one structured event. Remote addresses and raw Host are
// omitted unless the logger level is debug. Bodies, Authorization,
// Cookie, Set-Cookie, and PEM keys are never fields on this type.
type Record struct {
	Timestamp       time.Time
	Level           Level
	Event           string
	Component       string
	RequestID       string
	FlowID          string
	Host            string
	HostClass       string
	Capability      string
	Result          string
	ErrorCode       string
	DurationMS      float64
	StoreGeneration uint64
	// Remote is recorded only when the logger min level is debug.
	Remote string
}

// Logger writes slog JSON events. The default path writes synchronously so
// records are not silently buffered. WithQueue enables a non-blocking
// buffer that drops (and counts) on overflow.
type Logger struct {
	mu      sync.Mutex
	handler slog.Handler
	min     slog.Level
	q       *Queue[Record]
	reg     *Registry
	now     func() time.Time
	dropped atomic.Int64
	sync    bool
}

// ParseLevel maps YAML logLevel to a slog level. Unknown values are info.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

func slogLevel(l Level) slog.Level {
	switch l {
	case LevelDebug:
		return slog.LevelDebug
	case LevelWarn:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func recordSlogLevel(l Level) slog.Level {
	return slogLevel(l)
}

// NewLogger writes JSON lines to w on the calling goroutine. w may be nil (discard).
func NewLogger(w io.Writer, min Level) *Logger {
	if min == "" {
		min = LevelInfo
	}
	lvl := slogLevel(min)
	var h slog.Handler
	if w != nil {
		h = slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level:       lvl,
			ReplaceAttr: replaceLogAttr,
		})
	}
	return &Logger{
		handler: h,
		min:     lvl,
		now:     time.Now,
		sync:    true,
	}
}

func replaceLogAttr(_ []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case slog.TimeKey:
		a.Key = "timestamp"
	case slog.MessageKey:
		a.Key = "event"
	case slog.LevelKey:
		if v, ok := a.Value.Any().(slog.Level); ok {
			a.Value = slog.StringValue(strings.ToLower(v.String()))
		}
	}
	return a
}

// WithSync writes on the calling goroutine (the NewLogger default).
func (l *Logger) WithSync() *Logger {
	if l != nil {
		l.sync = true
	}
	return l
}

// WithQueue switches Log to a bounded TrySend buffer. A full queue never
// blocks; overflow increments Logger.Dropped.
func (l *Logger) WithQueue(n int) *Logger {
	if l == nil {
		return nil
	}
	l.sync = false
	if l.q == nil {
		l.q = NewQueue[Record](n)
	}
	return l
}

// WithMetrics records queue overflow on the catalog drop counter.
func (l *Logger) WithMetrics(r *Registry) *Logger {
	if l != nil {
		l.reg = r
	}
	return l
}

// Queue is the optional async buffer.
func (l *Logger) Queue() *Queue[Record] {
	if l == nil {
		return nil
	}
	return l.q
}

// Debug reports whether remote addresses and raw Host may be logged.
func (l *Logger) Debug() bool {
	return l != nil && l.min <= slog.LevelDebug
}

// Log redacts sensitive fields and either writes or enqueues.
func (l *Logger) Log(rec Record) {
	if l == nil {
		return
	}
	if rec.Timestamp.IsZero() && l.now != nil {
		rec.Timestamp = l.now().UTC()
	}
	if rec.Level == "" {
		rec.Level = LevelInfo
	}
	rec = l.redact(rec)
	if l.sync || l.q == nil {
		l.write(rec)
		return
	}
	if !l.q.TrySend(rec) {
		l.dropped.Add(1)
		if l.reg != nil {
			l.reg.Inc(MetricTelemetryDropped, map[string]string{"reason": "log"}, 1)
		}
	}
}

// Dropped is the number of records discarded by a full WithQueue buffer.
func (l *Logger) Dropped() int64 {
	if l == nil {
		return 0
	}
	return l.dropped.Load()
}

// Serve writes queued records until ctx is done, then drains. Use with WithQueue
// so Log never blocks the proxy on a slow sink.
func (l *Logger) Serve(ctx context.Context) {
	if l == nil || l.q == nil {
		return
	}
	for {
		select {
		case rec := <-l.q.Recv():
			l.write(rec)
		case <-ctx.Done():
			l.Drain()
			return
		}
	}
}

// Drain writes queued records to the sink until q is empty.
func (l *Logger) Drain() {
	if l == nil || l.q == nil {
		return
	}
	for {
		select {
		case rec := <-l.q.Recv():
			l.write(rec)
		default:
			return
		}
	}
}

func (l *Logger) redact(rec Record) Record {
	if rec.Host != "" && rec.HostClass == "" {
		rec.HostClass = ClassifyHost(rec.Host)
	}
	if rec.Host == "" && rec.HostClass == "" {
		// leave both empty
	}
	if l == nil || !l.Debug() {
		rec.Remote = ""
		// Closed: never put raw Host in info logs; host_class stays.
		rec.Host = ""
	}
	return rec
}

func (l *Logger) write(rec Record) {
	if l == nil || l.handler == nil {
		return
	}
	lvl := recordSlogLevel(rec.Level)
	if !l.handler.Enabled(context.Background(), lvl) {
		return
	}
	var attrs []slog.Attr
	if rec.Component != "" {
		attrs = append(attrs, slog.String("component", rec.Component))
	}
	if rec.RequestID != "" {
		attrs = append(attrs, slog.String("request_id", rec.RequestID))
	}
	if rec.FlowID != "" {
		attrs = append(attrs, slog.String("flow_id", rec.FlowID))
	}
	if rec.Host != "" {
		attrs = append(attrs, slog.String("host", rec.Host))
	}
	if rec.HostClass != "" {
		attrs = append(attrs, slog.String("host_class", rec.HostClass))
	}
	if rec.Capability != "" {
		attrs = append(attrs, slog.String("capability", rec.Capability))
	}
	if rec.Result != "" {
		attrs = append(attrs, slog.String("result", rec.Result))
	}
	if rec.ErrorCode != "" {
		attrs = append(attrs, slog.String("error_code", rec.ErrorCode))
	}
	if rec.DurationMS != 0 {
		attrs = append(attrs, slog.Float64("duration_ms", rec.DurationMS))
	}
	if rec.StoreGeneration != 0 {
		attrs = append(attrs, slog.Uint64("store_generation", rec.StoreGeneration))
	}
	if rec.Remote != "" {
		attrs = append(attrs, slog.String("remote", rec.Remote))
	}
	r := slog.NewRecord(rec.Timestamp, lvl, rec.Event, 0)
	r.AddAttrs(attrs...)
	// Serialize Handle so callers can pass a non-thread-safe io.Writer.
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.handler.Handle(context.Background(), r)
}

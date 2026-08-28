package app

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/audit"
	"github.com/hilather/go-lab-mitmproxy/internal/compiler"
	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/observability"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

const (
	defaultIdempotencyMax = 256
	defaultAuditMax       = 128
)

// Options constructs an App.
type Options struct {
	Snapshots      *snapshot.Store
	Inbox          *store.Memory
	Now            func() time.Time
	BootstrapPath  string
	IdempotencyMax int
	AuditMax       int
	Auditor        audit.Sink
	Metrics        *observability.Registry
	Logger         *observability.Logger
}

// App is the process-local Service implementation.
type App struct {
	mu            sync.Mutex
	snaps         *snapshot.Store
	inbox         *store.Memory
	now           func() time.Time
	bootstrapPath string
	idemp         *idempCache
	audit         *audit.Fanout
	resetHooks    []func()
	applyHooks    []func()
	replay        ReplayFunc
	metrics       *observability.Registry
	logger        *observability.Logger
	healthMu      sync.Mutex
	health        func() observability.Facts
}

var _ Service = (*App)(nil)

// New returns an App. A nil Snapshots becomes an empty snapshot.Store.
func New(opts Options) *App {
	if opts.Snapshots == nil {
		opts.Snapshots = snapshot.NewStore()
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	idempMax := opts.IdempotencyMax
	if idempMax <= 0 {
		idempMax = defaultIdempotencyMax
	}
	auditMax := opts.AuditMax
	if auditMax <= 0 {
		if snap := opts.Snapshots.Load(); snap != nil && snap.Canonical != nil && snap.Canonical.Spec.Observability.Audit.Ring > 0 {
			auditMax = snap.Canonical.Spec.Observability.Audit.Ring
		} else {
			auditMax = defaultAuditMax
		}
	}
	if opts.Inbox != nil {
		opts.Inbox.SetTelemetry(opts.Metrics, opts.Logger)
	}
	return &App{
		snaps:         opts.Snapshots,
		inbox:         opts.Inbox,
		now:           opts.Now,
		bootstrapPath: opts.BootstrapPath,
		idemp:         newIdempCache(idempMax),
		audit:         audit.NewFanout(auditMax, opts.Auditor),
		metrics:       opts.Metrics,
		logger:        opts.Logger,
	}
}

// Boot loads bootstrap YAML, compiles a snapshot, and opens the inbox.
func Boot(ctx context.Context, opts Options) (*App, error) {
	if opts.BootstrapPath == "" {
		return nil, domainerr.ValidationFailed("bootstrap path is required",
			domainerr.FieldViolation{Path: "bootstrapPath", Code: "required", Message: "bootstrap path is required"})
	}
	st, err := config.LoadFile(opts.BootstrapPath)
	if err != nil {
		return nil, asDomain(err)
	}
	snap, err := compiler.Compile(ctx, st, compiler.CompileOpts{})
	if err != nil {
		return nil, asDomain(err)
	}
	if opts.Inbox == nil {
		inbox, err := store.New(store.OptionsFromSpec(snap.Canonical.Spec.Store))
		if err != nil {
			return nil, asDomain(err)
		}
		opts.Inbox = inbox
	}
	if opts.Snapshots == nil {
		opts.Snapshots = snapshot.NewStore()
	}
	opts.Snapshots.InstallBootstrap(snap)
	return New(opts), nil
}

// Snapshots is the live config pointer the proxy re-reads per request / CONNECT.
func (s *App) Snapshots() *snapshot.Store {
	if s == nil {
		return nil
	}
	return s.snaps
}

// Inbox is the process-local flow store. Proxy inserts go here directly.
func (s *App) Inbox() *store.Memory {
	if s == nil {
		return nil
	}
	return s.inbox
}

// Active is the live snapshot, or nil.
func (s *App) Active() *snapshot.Snapshot {
	if s == nil || s.snaps == nil {
		return nil
	}
	return s.snaps.Load()
}

// Close wipes the inbox. It does not write the bootstrap file.
func (s *App) Close() {
	if s == nil || s.inbox == nil {
		return
	}
	s.inbox.Wipe()
}

// SetHealth installs live listener facts for Status.Ready / Evaluate.
// A nil fn restores the store-only default (listeners assumed up).
func (s *App) SetHealth(fn func() observability.Facts) {
	if s == nil {
		return
	}
	s.healthMu.Lock()
	s.health = fn
	s.healthMu.Unlock()
}

// HealthFacts is the input to observability.Evaluate. Without SetHealth,
// Ready means the inbox exists (HTTP-less / httptest default).
func (s *App) HealthFacts() observability.Facts {
	if s == nil {
		return observability.Facts{}
	}
	s.healthMu.Lock()
	fn := s.health
	s.healthMu.Unlock()
	storeUp := s.inbox != nil
	caReady := true
	origOff := true
	if snap := s.Active(); snap != nil {
		if snap.Spec().TLS.Intercept {
			caReady = snap.CA != nil
		}
		origOff = !snap.Spec().Listeners.OriginalDestination.Enabled
	}
	if fn != nil {
		f := fn()
		f.StoreUp = storeUp
		f.CAReady = caReady
		f.OrigDestOff = origOff
		return f
	}
	return observability.Facts{StoreUp: storeUp, ProxyBound: storeUp, MgmtBound: storeUp, CAReady: caReady, OrigDestOff: origOff}
}

func (s *App) requireCtx(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func (s *App) active() (*snapshot.Snapshot, error) {
	if s == nil || s.snaps == nil {
		return nil, domainerr.Internal("no snapshot store")
	}
	snap := s.snaps.Load()
	if snap == nil {
		return nil, domainerr.Internal("no active snapshot")
	}
	return snap, nil
}

func cloneState(st *model.State) (*model.State, error) {
	if st == nil {
		return nil, domainerr.ValidationFailed("nil state",
			domainerr.FieldViolation{Path: "", Code: "required", Message: "state is nil"})
	}
	b, err := json.Marshal(st)
	if err != nil {
		return nil, domainerr.Internal("clone marshal: " + err.Error())
	}
	var out model.State
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, domainerr.Internal("clone unmarshal: " + err.Error())
	}
	return &out, nil
}

func compileCandidate(ctx context.Context, st *model.State, prev *snapshot.Snapshot, now time.Time, ops []model.Operation) (*snapshot.Snapshot, error) {
	opts := compiler.CompileOpts{Now: now, Previous: prev}
	if prev != nil {
		opts.BootstrapRevision = prev.BootstrapRevision
		opts.Generation = prev.Generation + 1
		if opts.BootstrapRevision == "" {
			opts.BootstrapRevision = prev.Revision
		}
	}
	if prev == nil || anyReplaceHTTPAuth(ops) {
		opts.ReloadHTTPAuth = true
	}
	return compiler.Compile(ctx, st, opts)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

func asDomain(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := domainerr.As(err); ok {
		return err
	}
	return domainerr.Internal(err.Error())
}

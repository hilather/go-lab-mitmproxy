package app

import (
	"context"
	"errors"
	"os"
	"syscall"

	"github.com/hilather/go-lab-mitmproxy/internal/audit"
	"github.com/hilather/go-lab-mitmproxy/internal/compiler"
	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/observability"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

// ResetRuntime prepares process resources before Reset changes desired state or flows.
// Prepare runs under the mutation lock. Commit must be infallible and nonblocking;
// Rollback releases only staged resources. Neither callback may call mutations.
type ResetRuntime func(context.Context, model.Spec) (commit func(), rollback func(), err error)

// SetResetRuntime installs the process resource reconciler (the CLI composition root).
func (s *App) SetResetRuntime(fn ResetRuntime) {
	s.mu.Lock()
	s.resetRuntime = fn
	s.mu.Unlock()
}

// Reset rereads the bootstrap mount, compiles, wipes the inbox, and swaps
// only after success. It never writes the bootstrap file. A missing or
// invalid file leaves the active snapshot and inbox unchanged.
// Generate-mode CA rotates because Compile is not given Previous.
func (s *App) Reset(ctx context.Context, actor Actor, in ResetIn) (*ApplyResult, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	res, hooks, err := s.resetLocked(ctx, actor, in)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	for _, fn := range hooks {
		fn()
	}
	return res, nil
}

func (s *App) resetLocked(ctx context.Context, actor Actor, in ResetIn) (*ApplyResult, []func(), error) {
	prev := s.snaps.Load()
	gen := model.Generation(0)
	if prev != nil {
		gen = prev.Generation + 1
	}

	next, err := s.loadBootstrapCandidate(ctx, gen)
	if err != nil {
		return nil, nil, err
	}

	diff, _, err := diffStates(canonicalOf(prev), next.Canonical)
	if err != nil {
		return nil, nil, err
	}

	var commit, rollback func()
	if s.resetRuntime != nil {
		commit, rollback, err = s.resetRuntime(ctx, next.Spec())
		if err != nil {
			if errors.Is(err, syscall.EADDRINUSE) {
				return nil, nil, domainerr.ValidationFailed("Reset listener address is already in use: " + err.Error()).
					WithRemediation("Free the occupied address or choose a nonoverlapping address in bootstrap YAML, then Reset. If it overlaps an active listener, restart the process or Reset through a free intermediate port.")
			}
			return nil, nil, asDomain(err)
		}
		if rollback != nil {
			defer rollback()
		}
	}

	// Validate new store options (including creatable spill dir) before
	// Wipe so a failed Reset cannot empty the inbox under the old snapshot.
	if s.inbox != nil {
		opts, err := store.CheckOptions(store.OptionsFromSpec(next.Canonical.Spec.Store))
		if err != nil {
			return nil, nil, asDomain(err)
		}
		if err := s.inbox.ResetTo(opts); err != nil {
			return nil, nil, asDomain(err)
		}
	}

	displaced := s.snaps.Swap(next)
	s.snaps.SetBootstrap(next)
	if commit != nil {
		commit()
	}
	s.idemp.clear()
	hooks := append([]func(){}, s.resetHooks...)

	res := &ApplyResult{
		Plan:            *s.planFrom(&candidate{prev: displaced, next: next, diff: diff}),
		Applied:         true,
		Generation:      next.Generation,
		RuntimeRevision: next.Revision,
	}
	if s.logger != nil {
		s.logger.Log(observability.Record{
			Event:           observability.EventStateReset,
			Component:       "app",
			Result:          "ok",
			StoreGeneration: storeGeneration(s.inbox),
		})
	}
	res.AuditEventID = s.recordAudit(ctx, audit.Event{
		Time:            s.now(),
		ActorID:         actor.ID,
		ActorClass:      actor.Class,
		Transport:       actor.Transport,
		Capability:      "state.reset",
		Reason:          in.Reason,
		Revision:        next.Revision,
		Previous:        revisionOf(displaced),
		StoreGeneration: storeGeneration(s.inbox),
		Result:          audit.ResultOK,
		Diff:            toAuditDiff(diff),
	})
	return cloneApply(res), hooks, nil
}

func (s *App) loadBootstrapCandidate(ctx context.Context, gen model.Generation) (*snapshot.Snapshot, error) {
	if s.bootstrapPath != "" {
		if _, err := os.Stat(s.bootstrapPath); err != nil {
			if os.IsNotExist(err) {
				return nil, domainerr.ValidationFailed("bootstrap file unavailable",
					domainerr.FieldViolation{Path: "bootstrapPath", Code: "required", Message: "bootstrap file is missing; active snapshot unchanged"})
			}
			return nil, domainerr.Internal("stat bootstrap: " + err.Error())
		}
		st, err := config.LoadFile(s.bootstrapPath)
		if err != nil {
			return nil, asDomain(err)
		}
		// No Previous: generate-mode CA rotates on reset.
		snap, err := compiler.Compile(ctx, st, compiler.CompileOpts{
			Now:        s.now(),
			Generation: gen,
			RotateCA:   true,
		})
		if err != nil {
			return nil, asDomain(err)
		}
		return snap, nil
	}
	boot := s.snaps.Bootstrap()
	if boot == nil || boot.Canonical == nil {
		return nil, domainerr.ValidationFailed("no bootstrap snapshot",
			domainerr.FieldViolation{Path: "bootstrap", Code: "required", Message: "no bootstrap path or snapshot to reset to"})
	}
	copied, err := cloneState(boot.Canonical)
	if err != nil {
		return nil, err
	}
	snap, err := compiler.Compile(ctx, copied, compiler.CompileOpts{
		Now:        s.now(),
		Generation: gen,
		RotateCA:   true,
	})
	if err != nil {
		return nil, asDomain(err)
	}
	return snap, nil
}

func canonicalOf(s *snapshot.Snapshot) *model.State {
	if s == nil {
		return nil
	}
	return s.Canonical
}

func storeGeneration(inbox *store.Memory) uint64 {
	if inbox == nil {
		return 0
	}
	return inbox.Generation()
}

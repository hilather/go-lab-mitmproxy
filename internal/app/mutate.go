package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/hilather/go-lab-mitmproxy/internal/audit"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

type candidate struct {
	prev *snapshot.Snapshot
	next *snapshot.Snapshot
	ops  []model.Operation
	diff []DiffEntry
	warn []Warning
}

// Plan dry-runs the mutation pipeline. expectedRevision is required.
func (s *App) Plan(ctx context.Context, actor Actor, in ChangeIn) (*Plan, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.planLocked(ctx, in)
}

func (s *App) planLocked(ctx context.Context, in ChangeIn) (*Plan, error) {
	fp, err := fingerprintChange(in)
	if err != nil {
		return nil, err
	}
	if hit, err := s.idemp.lookup(in.IdempotencyKey, fp); err != nil {
		return nil, err
	} else if hit != nil && hit.plan != nil {
		return clonePlan(hit.plan), nil
	}
	cand, err := s.buildCandidate(ctx, in, true)
	if err != nil {
		s.forgetIdempOnConflict(in.IdempotencyKey, err)
		return nil, err
	}
	if err := s.checkStoreCaps(cand, in.Force, false); err != nil {
		return nil, err
	}
	p := s.planFrom(cand)
	s.idemp.storePlan(in.IdempotencyKey, fp, p)
	return clonePlan(p), nil
}

// Apply compiles the candidate and atomically swaps only after success.
func (s *App) Apply(ctx context.Context, actor Actor, in ChangeIn) (*ApplyResult, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	res, hooks, err := s.applyLocked(ctx, actor, in)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	for _, fn := range hooks {
		fn()
	}
	return res, nil
}

func (s *App) applyLocked(ctx context.Context, actor Actor, in ChangeIn) (*ApplyResult, []func(), error) {
	fp, err := fingerprintChange(in)
	if err != nil {
		return nil, nil, err
	}
	if hit, err := s.idemp.lookup(in.IdempotencyKey, fp); err != nil {
		return nil, nil, err
	} else if hit != nil && hit.apply != nil {
		// Replay is not a new commit — do not fire OnApply (cursor rotation).
		return cloneApply(hit.apply), nil, nil
	}
	cand, err := s.buildCandidate(ctx, in, true)
	if err != nil {
		s.forgetIdempOnConflict(in.IdempotencyKey, err)
		return nil, nil, err
	}
	if err := s.checkStoreCaps(cand, in.Force, true); err != nil {
		return nil, nil, err
	}
	prev := s.snaps.Swap(cand.next)
	res := &ApplyResult{
		Plan:            *s.planFrom(cand),
		Applied:         true,
		Generation:      cand.next.Generation,
		RuntimeRevision: cand.next.Revision,
	}
	res.AuditEventID = s.recordAudit(ctx, audit.Event{
		Time:       s.now(),
		ActorID:    actor.ID,
		ActorClass: actor.Class,
		Transport:  actor.Transport,
		Capability: "changes.apply",
		Reason:     in.Reason,
		Revision:   cand.next.Revision,
		Previous:   revisionOf(prev),
		Result:     audit.ResultOK,
		Diff:       toAuditDiff(cand.diff),
	})
	s.idemp.storeApply(in.IdempotencyKey, fp, res)
	return cloneApply(res), append([]func(){}, s.applyHooks...), nil
}

// Validate inspects a candidate document and/or operations. It never swaps
// and does not require expectedRevision.
func (s *App) Validate(ctx context.Context, actor Actor, in ValidateIn) (*Plan, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	s.mu.Lock()
	defer s.mu.Unlock()
	var prev *snapshot.Snapshot
	var base *model.State
	if in.State != nil {
		copied, err := cloneState(in.State)
		if err != nil {
			return nil, err
		}
		base = copied
		prev = s.snaps.Load()
	} else {
		snap, err := s.active()
		if err != nil {
			return nil, err
		}
		prev = snap
		copied, err := cloneState(snap.Canonical)
		if err != nil {
			return nil, err
		}
		base = copied
	}
	if err := applyOperations(base, in.Operations); err != nil {
		return nil, err
	}
	next, err := compileCandidate(ctx, base, prev, s.now())
	if err != nil {
		return nil, asDomain(err)
	}
	before := prev
	var beforeState *model.State
	if before != nil {
		beforeState = before.Canonical
	} else {
		beforeState = in.State
	}
	diff, _, err := diffStates(beforeState, next.Canonical)
	if err != nil {
		return nil, err
	}
	return clonePlan(s.planFrom(&candidate{
		prev: prev,
		next: next,
		ops:  append([]model.Operation(nil), in.Operations...),
		diff: diff,
	})), nil
}

func (s *App) buildCandidate(ctx context.Context, in ChangeIn, requireRev bool) (*candidate, error) {
	prev, err := s.active()
	if err != nil {
		return nil, err
	}
	if requireRev {
		if in.ExpectedRevision == "" {
			return nil, domainerr.ValidationFailed("expectedRevision is required",
				domainerr.FieldViolation{Path: "expectedRevision", Code: "required", Message: "expectedRevision is required for plan and apply"})
		}
		if in.ExpectedRevision != prev.Revision {
			return nil, domainerr.RevisionConflict("active revision does not match expectedRevision", string(prev.Revision)).
				WithRemediation("Re-read GET state and re-plan against the current revision.")
		}
	}
	copied, err := cloneState(prev.Canonical)
	if err != nil {
		return nil, err
	}
	if err := applyOperations(copied, in.Operations); err != nil {
		return nil, err
	}
	next, err := compileCandidate(ctx, copied, prev, s.now())
	if err != nil {
		return nil, asDomain(err)
	}
	diff, _, err := diffStates(prev.Canonical, next.Canonical)
	if err != nil {
		return nil, err
	}
	return &candidate{
		prev: prev,
		next: next,
		ops:  append([]model.Operation(nil), in.Operations...),
		diff: diff,
	}, nil
}

func (s *App) checkStoreCaps(cand *candidate, force, apply bool) error {
	if s.inbox == nil || cand == nil || cand.next == nil || cand.next.Canonical == nil {
		return nil
	}
	if !anyReplaceStoreCaps(cand.ops) {
		return nil
	}
	spec := cand.next.Canonical.Spec.Store
	stats := s.inbox.Stats()
	over := stats.FlowCount > spec.MaxFlows || stats.Bytes > spec.MaxBytes
	if !over {
		if apply {
			if err := s.inbox.ReplaceCaps(store.OptionsFromSpec(spec), force); err != nil {
				return mapStoreCapErr(err)
			}
		}
		return nil
	}
	if spec.FullPolicy != model.FullPolicyEvictOldest && !force {
		return domainerr.StoreOverNewCap("inbox occupancy exceeds the new store caps")
	}
	n := stats.FlowCount - spec.MaxFlows
	if n < 0 {
		n = 0
	}
	cand.warn = append(cand.warn, Warning{
		Code:    "store_evict",
		Message: fmt.Sprintf("apply evicts oldest flows to fit new caps (at least %d)", n),
	})
	if apply {
		if err := s.inbox.ReplaceCaps(store.OptionsFromSpec(spec), force); err != nil {
			return mapStoreCapErr(err)
		}
	}
	return nil
}

func mapStoreCapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, store.ErrOverNewCap) {
		return domainerr.StoreOverNewCap("inbox occupancy exceeds the new store caps")
	}
	return asDomain(err)
}

func (s *App) planFrom(c *candidate) *Plan {
	prevRev := model.Revision("")
	if c.prev != nil {
		prevRev = c.prev.Revision
	}
	p := &Plan{
		PreviousRevision:  prevRev,
		CandidateRevision: c.next.Revision,
		Drifted:           c.next.Drifted(),
		Diff:              c.diff,
		Warnings:          c.warn,
		Operations:        append([]model.Operation(nil), c.ops...),
	}
	return p
}

func (s *App) forgetIdempOnConflict(key string, err error) {
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeRevisionConflict {
		return
	}
	s.idemp.evict(key)
}

func revisionOf(s *snapshot.Snapshot) model.Revision {
	if s == nil {
		return ""
	}
	return s.Revision
}

func toAuditDiff(in []DiffEntry) []audit.RedactedEntry {
	if len(in) == 0 {
		return nil
	}
	out := make([]audit.RedactedEntry, len(in))
	for i, d := range in {
		out[i] = audit.RedactedEntry{Path: d.Path, Op: d.Op, Before: d.Before, After: d.After}
	}
	return out
}

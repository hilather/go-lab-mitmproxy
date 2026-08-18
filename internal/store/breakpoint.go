package store

import (
	"context"
	"errors"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

type pauseWaiter struct {
	ch chan pauseResult
}

type pauseResult struct {
	patch ResumePatch
	err   error
}

// Pause sets State=paused and emits Event{Kind:"paused"}.
func (m *Memory) Pause(id string) error {
	if m == nil {
		return errors.New("store: nil Memory")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[id]
	if !ok {
		return ErrNotFound
	}
	if rec.flow.State == model.FlowStatePaused {
		return nil
	}
	rec.flow.State = model.FlowStatePaused
	m.generation++
	m.cond.Broadcast()
	m.emitLocked(Event{Kind: EventPaused, ID: id, Gen: m.generation})
	return nil
}

// Resume applies an optional patch, unblocks WaitPaused, and marks the flow
// completed (response-phase) or open (request-phase).
func (m *Memory) Resume(id string, patch *ResumePatch) error {
	if m == nil {
		return errors.New("store: nil Memory")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[id]
	if !ok {
		return ErrNotFound
	}
	if rec.flow.State != model.FlowStatePaused {
		return ErrBreakpointInactive
	}
	applied := ResumePatch{}
	if patch != nil {
		if err := m.applyPatchLocked(rec, *patch); err != nil {
			return err
		}
		applied = snapshotPatch(*patch, rec.flow)
	} else {
		applied = currentPatch(rec.flow)
	}
	if rec.flow.PausedPhase == model.RulePhaseRequest {
		rec.flow.State = model.FlowStateOpen
	} else {
		rec.flow.State = model.FlowStateCompleted
	}
	m.generation++
	m.finishPausedLocked(id, pauseResult{patch: applied})
	m.cond.Broadcast()
	m.emitLocked(Event{Kind: EventResumed, ID: id, Gen: m.generation})
	return nil
}

// Drop marks State=dropped and unblocks WaitPaused with ErrDropped.
func (m *Memory) Drop(id string) error {
	if m == nil {
		return errors.New("store: nil Memory")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[id]
	if !ok {
		return ErrNotFound
	}
	if rec.flow.State != model.FlowStatePaused {
		return ErrBreakpointInactive
	}
	rec.flow.State = model.FlowStateDropped
	m.generation++
	m.finishPausedLocked(id, pauseResult{err: ErrDropped})
	m.cond.Broadcast()
	m.emitLocked(Event{Kind: EventDropped, ID: id, Gen: m.generation})
	return nil
}

// WaitPaused blocks until Resume, Drop, Wipe/ResetTo, or ctx cancellation.
// The timeout lives in ctx — the store does not start a timer that outlives Wipe.
func (m *Memory) WaitPaused(ctx context.Context, id string) (ResumePatch, error) {
	if m == nil {
		return ResumePatch{}, errors.New("store: nil Memory")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	rec, ok := m.byID[id]
	if !ok {
		m.mu.Unlock()
		return ResumePatch{}, ErrNotFound
	}
	if rec.flow.State != model.FlowStatePaused {
		m.mu.Unlock()
		return ResumePatch{}, ErrBreakpointInactive
	}
	w := &pauseWaiter{ch: make(chan pauseResult, 1)}
	m.paused[id] = append(m.paused[id], w)
	m.mu.Unlock()

	select {
	case <-ctx.Done():
		m.mu.Lock()
		m.removeWaiterLocked(id, w)
		m.mu.Unlock()
		// Resume/Drop may have won the race; prefer that result.
		select {
		case res := <-w.ch:
			return res.patch, res.err
		default:
			return ResumePatch{}, ctx.Err()
		}
	case res := <-w.ch:
		return res.patch, res.err
	}
}

func (m *Memory) applyPatchLocked(rec *record, patch ResumePatch) error {
	if patch.Body != nil && int64(len(patch.Body)) > m.maxBodyBytes {
		return ErrTooLarge
	}
	trial := cloneFlow(rec.flow)
	side := &trial.Request
	if trial.PausedPhase == model.RulePhaseResponse {
		side = &trial.Response
	}
	if patch.Headers != nil {
		side.Headers = cloneHeaders(patch.Headers)
	}
	if patch.Body != nil {
		side.Body = cloneBytes(patch.Body)
		side.Size = len(patch.Body)
		side.Truncated = false
	}
	next := trial.ResidentBytes()
	if next > m.maxBytes {
		return ErrTooLarge
	}
	old := rec.resident
	if next-old > 0 && m.bytes+(next-old) > m.maxBytes && m.fullPolicy != model.FullPolicyEvictOldest {
		return ErrFull
	}
	rec.flow = trial
	rec.resident = next
	m.bytes += next - old
	if m.bytes < 0 {
		m.bytes = 0
	}
	return nil
}

func snapshotPatch(patch ResumePatch, f *model.Flow) ResumePatch {
	out := ResumePatch{}
	if patch.Headers != nil {
		out.Headers = cloneHeaders(patch.Headers)
	} else {
		out.Headers = cloneHeaders(currentSide(f).Headers)
	}
	if patch.Body != nil {
		out.Body = cloneBytes(patch.Body)
	} else {
		out.Body = cloneBytes(currentSide(f).Body)
	}
	return out
}

func currentPatch(f *model.Flow) ResumePatch {
	side := currentSide(f)
	return ResumePatch{
		Headers: cloneHeaders(side.Headers),
		Body:    cloneBytes(side.Body),
	}
}

func currentSide(f *model.Flow) *model.HTTPMessage {
	if f.PausedPhase == model.RulePhaseResponse {
		return &f.Response
	}
	return &f.Request
}

func (m *Memory) finishPausedLocked(id string, res pauseResult) {
	for _, w := range m.paused[id] {
		select {
		case w.ch <- res:
		default:
		}
	}
	delete(m.paused, id)
}

func (m *Memory) failPausedLocked(err error) {
	for id, waiters := range m.paused {
		for _, w := range waiters {
			select {
			case w.ch <- pauseResult{err: err}:
			default:
			}
		}
		delete(m.paused, id)
	}
}

func (m *Memory) removeWaiterLocked(id string, w *pauseWaiter) {
	list := m.paused[id]
	for i, x := range list {
		if x == w {
			m.paused[id] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(m.paused[id]) == 0 {
		delete(m.paused, id)
	}
}

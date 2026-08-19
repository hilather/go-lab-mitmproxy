package app

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/audit"
	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

func (s *App) requireInbox() error {
	if s == nil || s.inbox == nil {
		return domainerr.Internal("no inbox")
	}
	return nil
}

func (s *App) matchStoreGeneration(in DeleteIn) error {
	if in.ExpectedStoreGeneration == nil || s.inbox == nil {
		return nil
	}
	cur := s.inbox.Generation()
	if cur != *in.ExpectedStoreGeneration {
		return domainerr.RevisionConflict("store generation does not match", strconv.FormatUint(cur, 10))
	}
	return nil
}

// ListFlows is a filtered inbox page. Proxy insert is not on this path.
func (s *App) ListFlows(ctx context.Context, actor Actor, q model.ListQuery) (model.ListResult, error) {
	if err := s.requireCtx(ctx); err != nil {
		return model.ListResult{}, err
	}
	_ = actor
	if err := s.requireInbox(); err != nil {
		return model.ListResult{}, err
	}
	return s.inbox.List(q)
}

// GetFlow loads one flow.
func (s *App) GetFlow(ctx context.Context, actor Actor, id string) (*model.Flow, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	if err := s.requireInbox(); err != nil {
		return nil, err
	}
	f, err := s.inbox.Get(id)
	if err != nil {
		return nil, mapStoreErr(err)
	}
	return f, nil
}

// DeleteFlow removes one flow and audits.
func (s *App) DeleteFlow(ctx context.Context, actor Actor, id string, in DeleteIn) error {
	if err := s.requireCtx(ctx); err != nil {
		return err
	}
	if err := s.requireInbox(); err != nil {
		return err
	}
	if err := s.matchStoreGeneration(in); err != nil {
		return err
	}
	if err := s.inbox.Delete(id); err != nil {
		return mapStoreErr(err)
	}
	s.recordAudit(ctx, audit.Event{
		Time:            s.now(),
		ActorID:         actor.ID,
		ActorClass:      actor.Class,
		Transport:       actor.Transport,
		Capability:      "flows.delete",
		FlowID:          id,
		StoreGeneration: s.inbox.Generation(),
		Result:          audit.ResultOK,
	})
	return nil
}

// ClearFlows empties the inbox without bumping epoch.
func (s *App) ClearFlows(ctx context.Context, actor Actor, in DeleteIn) (int, error) {
	if err := s.requireCtx(ctx); err != nil {
		return 0, err
	}
	if err := s.requireInbox(); err != nil {
		return 0, err
	}
	if err := s.matchStoreGeneration(in); err != nil {
		return 0, err
	}
	n, err := s.inbox.DeleteAll()
	if err != nil {
		return 0, mapStoreErr(err)
	}
	s.recordAudit(ctx, audit.Event{
		Time:            s.now(),
		ActorID:         actor.ID,
		ActorClass:      actor.Class,
		Transport:       actor.Transport,
		Capability:      "flows.clear",
		StoreGeneration: s.inbox.Generation(),
		Result:          audit.ResultOK,
	})
	return n, nil
}

// Wait returns the newest matching flow or a timeout domain error.
func (s *App) Wait(ctx context.Context, actor Actor, in WaitIn) (*model.Flow, error) {
	if err := s.requireCtx(ctx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, domainerr.Timeout("wait timed out")
		}
		return nil, err
	}
	_ = actor
	if err := s.requireInbox(); err != nil {
		return nil, err
	}
	timeout := in.Timeout
	if timeout <= 0 {
		timeout = DefaultWaitTimeout
	}
	maxWait := config.DefaultStoreMaxWait
	if snap := s.Active(); snap != nil && snap.Canonical != nil && snap.Canonical.Spec.Store.MaxWait > 0 {
		maxWait = snap.Canonical.Spec.Store.MaxWait
	}
	if timeout > maxWait {
		timeout = maxWait
	}
	if dl, ok := ctx.Deadline(); ok {
		remain := time.Until(dl)
		if remain <= 0 {
			return nil, domainerr.Timeout("wait timed out")
		}
		if remain < timeout {
			timeout = remain
		}
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	f, err := s.inbox.Wait(wctx, in.Filter)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, domainerr.Timeout("wait timed out")
		}
		return nil, mapStoreErr(err)
	}
	return f, nil
}

// Resume unblocks a paused breakpoint.
func (s *App) Resume(ctx context.Context, actor Actor, id string, patch *store.ResumePatch) error {
	if err := s.requireCtx(ctx); err != nil {
		return err
	}
	if err := s.requireInbox(); err != nil {
		return err
	}
	if err := s.inbox.Resume(id, patch); err != nil {
		return mapStoreErr(err)
	}
	s.recordAudit(ctx, audit.Event{
		Time:            s.now(),
		ActorID:         actor.ID,
		ActorClass:      actor.Class,
		Transport:       actor.Transport,
		Capability:      "flows.resume",
		FlowID:          id,
		StoreGeneration: s.inbox.Generation(),
		Result:          audit.ResultOK,
	})
	return nil
}

// Drop unblocks a paused breakpoint as dropped.
func (s *App) Drop(ctx context.Context, actor Actor, id string) error {
	if err := s.requireCtx(ctx); err != nil {
		return err
	}
	if err := s.requireInbox(); err != nil {
		return err
	}
	if err := s.inbox.Drop(id); err != nil {
		return mapStoreErr(err)
	}
	s.recordAudit(ctx, audit.Event{
		Time:            s.now(),
		ActorID:         actor.ID,
		ActorClass:      actor.Class,
		Transport:       actor.Transport,
		Capability:      "flows.drop",
		FlowID:          id,
		StoreGeneration: s.inbox.Generation(),
		Result:          audit.ResultOK,
	})
	return nil
}

// Subscribe fans out inbox membership events. cancel must be called.
func (s *App) Subscribe(ctx context.Context, actor Actor, buffer int) (<-chan FlowEvent, func()) {
	_ = ctx
	_ = actor
	if s == nil || s.inbox == nil {
		ch := make(chan FlowEvent)
		close(ch)
		return ch, func() {}
	}
	src, cancelSrc := s.inbox.Subscribe(buffer)
	if buffer <= 0 {
		buffer = 16
	}
	out := make(chan FlowEvent, buffer)
	done := make(chan struct{})
	go func() {
		defer close(out)
		for {
			select {
			case <-done:
				return
			case ev, ok := <-src:
				if !ok {
					return
				}
				next := FlowEvent{Type: mapFlowEvent(ev.Kind), ID: ev.ID, Host: ev.Host, Generation: ev.Gen}
				select {
				case out <- next:
				case <-done:
					return
				}
			}
		}
	}()
	var once sync.Once
	return out, func() {
		once.Do(func() {
			close(done)
			cancelSrc()
		})
	}
}

// OnReset registers a hook invoked after a successful Reset (cursor rotation).
func (s *App) OnReset(fn func()) {
	if s == nil || fn == nil {
		return
	}
	s.mu.Lock()
	s.resetHooks = append(s.resetHooks, fn)
	s.mu.Unlock()
}

// OnApply registers a hook invoked after a successful Apply.
func (s *App) OnApply(fn func()) {
	if s == nil || fn == nil {
		return
	}
	s.mu.Lock()
	s.applyHooks = append(s.applyHooks, fn)
	s.mu.Unlock()
}

func mapFlowEvent(kind string) string {
	switch kind {
	case store.EventInserted:
		return FlowCaptured
	case store.EventPaused:
		return FlowPaused
	case store.EventResumed:
		return FlowResumed
	case store.EventDropped:
		return FlowDropped
	case store.EventDeleted:
		return FlowDeleted
	case store.EventWiped:
		return StoreWiped
	default:
		return kind
	}
}

func mapStoreErr(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := domainerr.As(err); ok {
		return err
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		return domainerr.NotFound("flow not found")
	case errors.Is(err, store.ErrFull):
		return domainerr.StoreFull("inbox is full")
	case errors.Is(err, store.ErrOverNewCap):
		return domainerr.StoreOverNewCap("inbox occupancy exceeds the new store caps")
	case errors.Is(err, store.ErrBreakpointInactive):
		return domainerr.BreakpointInactive("breakpoint is not active")
	case errors.Is(err, store.ErrStaleEpoch):
		return domainerr.RevisionConflict("store epoch is stale", "")
	default:
		return asDomain(err)
	}
}

package app

import (
	"context"
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/audit"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// ReplayFunc is the origin-dial replay hook. cmd wires proxy.Server.Replay
// so this package does not import internal/proxy (Dial stays isolated).
type ReplayFunc func(ctx context.Context, stored *model.Flow) (*model.Flow, error)

// SetReplay installs the origin-dial implementation (proxy.Server.Replay).
func (s *App) SetReplay(fn ReplayFunc) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.replay = fn
	s.mu.Unlock()
}

// Replay fetches a stored flow and re-issues it to the origin via the wired hook.
func (s *App) Replay(ctx context.Context, actor Actor, id string) (*model.Flow, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	stored, err := s.GetFlow(ctx, actor, id)
	if err != nil {
		return nil, err
	}
	if err := validateReplay(stored); err != nil {
		return nil, err
	}
	s.mu.Lock()
	fn := s.replay
	s.mu.Unlock()
	if fn == nil {
		return nil, domainerr.Internal("replay is not wired")
	}
	out, err := fn(ctx, stored)
	if err != nil {
		return nil, asDomain(err)
	}
	s.recordAudit(ctx, audit.Event{
		Time:            s.now(),
		ActorID:         actor.ID,
		ActorClass:      actor.Class,
		Transport:       actor.Transport,
		Capability:      "flows.replay",
		FlowID:          id,
		StoreGeneration: s.inbox.Generation(),
		Result:          audit.ResultOK,
	})
	return out, nil
}

func validateReplay(f *model.Flow) error {
	if f == nil {
		return domainerr.ValidationFailed("flow is required",
			domainerr.FieldViolation{Path: "id", Code: "required", Message: "flow is required"})
	}
	if strings.EqualFold(f.Method, "CONNECT") || f.Protocol == model.FlowProtocolConnect {
		return domainerr.ValidationFailed("CONNECT flows cannot be replayed",
			domainerr.FieldViolation{Path: "protocol", Code: "invalid_value", Message: "CONNECT-metadata flows cannot be replayed"})
	}
	if f.Protocol == model.FlowProtocolWebSocket {
		return domainerr.ValidationFailed("websocket flows cannot be replayed",
			domainerr.FieldViolation{Path: "protocol", Code: "invalid_value", Message: "websocket flows cannot be replayed"})
	}
	if f.HTTP2 != nil && f.HTTP2.Pushed {
		return domainerr.ValidationFailed("pushed flows cannot be replayed",
			domainerr.FieldViolation{Path: "http2.pushed", Code: "invalid_value", Message: "PUSH_PROMISE flows cannot be replayed"})
	}
	if f.Request.Truncated {
		return domainerr.ValidationFailed("truncated request cannot be replayed",
			domainerr.FieldViolation{Path: "request", Code: "invalid_value", Message: "truncated request cannot be replayed"})
	}
	return nil
}

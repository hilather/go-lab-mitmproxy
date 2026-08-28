package rules

import (
	"maps"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// Caps match config.MaxRuleDelay / MaxBreakpointTimeout / MaxRuleBodyReplace
// so eval stays fail-closed even if a test-constructed snapshot skipped validate.
const (
	MaxDelay               = 30 * time.Second
	MinBreakpointTimeout   = time.Second
	MaxBreakpointTimeout   = 60 * time.Second
	MaxBodyReplace         = 64 << 10
	ActionBodySkipped      = "body_skipped"
	ActionLateSkip         = "late_skip"
	ActionBreakpointTO     = "breakpoint_timeout"
	DefaultDropStatus      = 403
	DefaultSyntheticStatus = 502
	MinHangTimeout         = time.Second
	MaxHangTimeout         = 30 * time.Second
	FlowErrorSilent        = "rule_silent"
	FlowErrorHang          = "rule_hang"
)

// Engine is a first-match evaluator. Tests construct it from model.RulesSpec
// (no compiler). Live apply later swaps a new Engine; in-flight sessions keep
// the Engine they loaded.
type Engine struct {
	enabled bool
	items   []model.RuleSpec
}

// New copies spec into an immutable evaluator. enabled:false matches nothing.
func New(spec model.RulesSpec) *Engine {
	e := &Engine{enabled: spec.Enabled}
	if !spec.Enabled || len(spec.Items) == 0 {
		return e
	}
	e.items = make([]model.RuleSpec, len(spec.Items))
	for i := range spec.Items {
		e.items[i] = cloneItem(spec.Items[i])
	}
	return e
}

// Enabled is the master switch.
func (e *Engine) Enabled() bool {
	return e != nil && e.enabled
}

// Hit is the winning enabled item.
type Hit struct {
	ID     string
	Phase  string
	Action model.RuleActionSpec
}

// Request is match input. Path is the decoded URL path (no query). Headers
// are the side being matched (request headers in request phase, response
// headers in response phase).
type Request struct {
	Host      string
	Path      string
	Method    string
	Headers   []model.Header
	Protocol  string
	Opcode    string
	Direction string
	Payload   []byte
}

// Match returns the first enabled item whose AND match succeeds for phase.
// Nil engine, disabled master switch, or no match → nil.
func (e *Engine) Match(phase string, in Request) *Hit {
	if e == nil || !e.enabled {
		return nil
	}
	for i := range e.items {
		item := e.items[i]
		if !item.Enabled {
			continue
		}
		if item.Phase != "" && item.Phase != phase {
			continue
		}
		if !matchAND(item.Match, in) {
			continue
		}
		return &Hit{ID: item.ID, Phase: item.Phase, Action: item.Action}
	}
	return nil
}

// HasEnabledWebSocket reports whether any enabled item is phase websocket.
// Walks Engine items; never Match("websocket", Request{}).
func (e *Engine) HasEnabledWebSocket() bool {
	if e == nil || !e.enabled {
		return false
	}
	for i := range e.items {
		if e.items[i].Enabled && e.items[i].Phase == model.RulePhaseWebSocket {
			return true
		}
	}
	return false
}

// NeedsFramePayload reports whether the pump must load unmasked bytes before
// Match. Uses the same predicates as Match minus only payloadContains.
func (e *Engine) NeedsFramePayload(in Request, declared uint64, visCap int) bool {
	if e == nil || !e.enabled {
		return false
	}
	for i := range e.items {
		item := e.items[i]
		if !item.Enabled || item.Phase != model.RulePhaseWebSocket {
			continue
		}
		if !matchANDExceptPayload(item.Match, in) {
			continue
		}
		if item.Match.PayloadContains == "" {
			return false
		}
		if visCap < 0 || declared > uint64(visCap) {
			continue
		}
		return true
	}
	return false
}

func cloneItem(in model.RuleSpec) model.RuleSpec {
	out := in
	if in.Action.Headers.Set != nil {
		out.Action.Headers.Set = maps.Clone(in.Action.Headers.Set)
	}
	if in.Action.Headers.Remove != nil {
		out.Action.Headers.Remove = append([]string(nil), in.Action.Headers.Remove...)
	}
	return out
}

package rules

import (
	"sort"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// Mutates reports whether the winning action requires buffering to
// maxBodyBytes (D21). delay/header stay on the capture-only tee path.
func Mutates(hit *Hit) bool {
	if hit == nil {
		return false
	}
	switch hit.Action.Type {
	case model.ActionBody, model.ActionStatus, model.ActionDrop, model.ActionBreakpoint:
		return true
	default:
		return false
	}
}

// ClampDelay bounds sleep to [0, 30s].
func ClampDelay(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	if d > MaxDelay {
		return MaxDelay
	}
	return d
}

// ClampBreakpointTimeout bounds WaitPaused to [1s, 60s], then min(storeMaxWait)
// when storeMaxWait > 0.
func ClampBreakpointTimeout(d, storeMaxWait time.Duration) time.Duration {
	if d < MinBreakpointTimeout {
		d = MinBreakpointTimeout
	}
	if d > MaxBreakpointTimeout {
		d = MaxBreakpointTimeout
	}
	if storeMaxWait > 0 && d > storeMaxWait {
		d = storeMaxWait
	}
	return d
}

// StatusFor returns the client status for drop/status actions.
func StatusFor(hit *Hit) int {
	if hit == nil {
		return DefaultSyntheticStatus
	}
	if hit.Action.Status >= 400 && hit.Action.Status <= 599 {
		return hit.Action.Status
	}
	if hit.Action.Type == model.ActionDrop {
		return DefaultDropStatus
	}
	return DefaultSyntheticStatus
}

// ApplyHeaders removes then sets. Set keys are applied in sorted order so
// eval is deterministic (D12).
func ApplyHeaders(in []model.Header, spec model.RuleHeadersSpec) []model.Header {
	out := make([]model.Header, 0, len(in)+len(spec.Set))
	removed := map[string]bool{}
	for _, name := range spec.Remove {
		removed[strings.ToLower(name)] = true
	}
	for i := range in {
		if removed[strings.ToLower(in[i].Name)] {
			continue
		}
		out = append(out, in[i])
	}
	if len(spec.Set) == 0 {
		return out
	}
	keys := make([]string, 0, len(spec.Set))
	for k := range spec.Set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	setLower := map[string]bool{}
	for _, k := range keys {
		setLower[strings.ToLower(k)] = true
	}
	kept := out[:0]
	for i := range out {
		if setLower[strings.ToLower(out[i].Name)] {
			continue
		}
		kept = append(kept, out[i])
	}
	out = kept
	for _, k := range keys {
		out = append(out, model.Header{Name: k, Value: spec.Set[k]})
	}
	return out
}

// BodyReplace is the UTF-8 replace payload, or nil if this action does not
// replace the body. type=body always replaces (including empty). status/drop
// replace only when the YAML string is non-empty.
func BodyReplace(hit *Hit) (body []byte, replace bool) {
	if hit == nil {
		return nil, false
	}
	switch hit.Action.Type {
	case model.ActionBody:
		return []byte(hit.Action.Body.Replace), true
	case model.ActionStatus, model.ActionDrop:
		if hit.Action.Body.Replace == "" {
			return nil, false
		}
		return []byte(hit.Action.Body.Replace), true
	default:
		return nil, false
	}
}

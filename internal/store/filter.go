package store

import (
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func matchFilter(f *model.Flow, q model.FlowFilter) bool {
	if f == nil {
		return false
	}
	if q.Host != "" && !strings.EqualFold(f.Host, q.Host) {
		return false
	}
	if q.Method != "" && !strings.EqualFold(f.Method, q.Method) {
		return false
	}
	if q.Scheme != "" && f.Scheme != q.Scheme {
		return false
	}
	if q.Status != 0 && f.Status != q.Status {
		return false
	}
	if q.Intercepted != nil && f.Intercepted != *q.Intercepted {
		return false
	}
	if !q.After.IsZero() && !f.StartedAt.After(q.After) {
		return false
	}
	if q.PathPrefix != "" && !strings.HasPrefix(f.Path(), q.PathPrefix) {
		return false
	}
	if q.RuleID != "" && !hasRule(f.RuleIDs, q.RuleID) {
		return false
	}
	return true
}

func hasRule(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

package rules

import (
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func matchAND(m model.RuleMatchSpec, in Request) bool {
	if !matchHost(m.Host, in.Host) {
		return false
	}
	path := in.Path
	if path == "" {
		path = "/"
	}
	if m.PathExact != "" && path != m.PathExact {
		return false
	}
	if m.PathPrefix != "" && !strings.HasPrefix(path, m.PathPrefix) {
		return false
	}
	if m.Method != "" && !strings.EqualFold(m.Method, in.Method) {
		return false
	}
	if m.Protocol != "" && !strings.EqualFold(m.Protocol, in.Protocol) {
		return false
	}
	if !matchHeader(m, in.Headers) {
		return false
	}
	return true
}

// matchHost: empty pattern matches any. Exact (case-insensitive) or "*.suffix".
func matchHost(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return true
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suf := pattern[1:] // ".suffix"
		return strings.HasSuffix(host, suf) && host != strings.TrimPrefix(suf, ".")
	}
	return pattern == host
}

func matchHeader(m model.RuleMatchSpec, headers []model.Header) bool {
	if m.HeaderName == "" {
		return true
	}
	found := false
	for i := range headers {
		if !strings.EqualFold(headers[i].Name, m.HeaderName) {
			continue
		}
		found = true
		if m.HeaderContains == "" || strings.Contains(headers[i].Value, m.HeaderContains) {
			return true
		}
	}
	return found && m.HeaderContains == ""
}

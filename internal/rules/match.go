package rules

import (
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func matchAND(m model.RuleMatchSpec, in Request) bool {
	host := in.Host
	if auth := headerValue(in.Headers, ":authority"); auth != "" {
		host = authorityHost(auth)
	}
	if !matchHost(m.Host, host) {
		return false
	}
	path := in.Path
	if p := headerValue(in.Headers, ":path"); p != "" {
		path = pathComponent(p)
	}
	if path == "" {
		path = "/"
	}
	if m.PathExact != "" && path != m.PathExact {
		return false
	}
	if m.PathPrefix != "" && !strings.HasPrefix(path, m.PathPrefix) {
		return false
	}
	method := in.Method
	if meth := headerValue(in.Headers, ":method"); meth != "" {
		method = meth
	}
	if m.Method != "" && !strings.EqualFold(m.Method, method) {
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

func headerValue(hs []model.Header, name string) string {
	for i := range hs {
		if strings.EqualFold(hs[i].Name, name) {
			return hs[i].Value
		}
	}
	return ""
}

func pathComponent(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return "/"
	}
	return p
}

func authorityHost(auth string) string {
	auth = strings.TrimSpace(auth)
	if auth == "" {
		return ""
	}
	if strings.HasPrefix(auth, "[") {
		end := strings.Index(auth, "]")
		if end > 0 {
			return auth[1:end]
		}
		return auth
	}
	if i := strings.LastIndex(auth, ":"); i >= 0 {
		port := auth[i+1:]
		if port != "" && isAllDigits(port) {
			return auth[:i]
		}
	}
	return auth
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
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

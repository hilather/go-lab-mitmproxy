package config

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
)

// reservedExact are normalized names that are never legal, even as unknown fields.
var reservedExact = map[string]string{
	"socks":          "implies a SOCKS data plane",
	"socks5":         "implies a SOCKS data plane",
	"socks4":         "implies a SOCKS data plane",
	"tproxy":         "implies transparent TPROXY intercept",
	"transparent":    "implies transparent intercept",
	"reverseproxy":   "implies a reverse-proxy / ingress posture",
	"publicca":       "implies a public or well-known CA",
	"trustedroot":    "implies a public or well-known CA",
	"mitmproxyaddon": "implies the Python mitmproxy addon VM",
	"addon":          "implies a plugin / addon VM",
	"pythonaddon":    "implies a Python addon VM",
	"exploit":        "implies an attack-tool surface",
	"payloadgen":     "implies an attack-tool surface",
	"attack":         "implies an attack-tool surface",
	"sslstrip":       "implies SSL-stripping",
	"hstsstrip":      "implies HSTS stripping",
	"mitmproxy":      "implies wrapping the Python mitmproxy binary",
	"mitmdump":       "implies wrapping the Python mitmdump binary",
	"mitmweb":        "implies a mitmweb compat surface",
}

// reservedPrefixes match after dash/underscore/case normalize.
var reservedPrefixes = []struct {
	prefix string
	why    string
}{
	{"socks", "implies a SOCKS data plane"},
	{"tproxy", "implies transparent TPROXY intercept"},
	{"transparent", "implies transparent intercept"},
	{"reverseproxy", "implies a reverse-proxy / ingress posture"},
	{"publicca", "implies a public or well-known CA"},
	{"trustedroot", "implies a public or well-known CA"},
	{"mitmproxy", "implies wrapping the Python mitmproxy binary"},
	{"mitmdump", "implies wrapping the Python mitmdump binary"},
	{"mitmweb", "implies a mitmweb compat surface"},
	{"addon", "implies a plugin / addon VM"},
	{"pythonaddon", "implies a Python addon VM"},
	{"exploit", "implies an attack-tool surface"},
	{"payloadgen", "implies an attack-tool surface"},
	{"attack", "implies an attack-tool surface"},
	{"sslstrip", "implies SSL-stripping"},
	{"hstsstrip", "implies HSTS stripping"},
}

// normalizeKey strips leading dashes, dashes, underscores, and case.
func normalizeKey(k string) string {
	k = strings.TrimLeft(k, "-")
	var b strings.Builder
	b.Grow(len(k))
	for _, r := range k {
		if r == '-' || r == '_' {
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

func reservedReason(normalized string) string {
	if why, ok := reservedExact[normalized]; ok {
		return why
	}
	for _, p := range reservedPrefixes {
		if strings.HasPrefix(normalized, p.prefix) {
			return p.why
		}
	}
	return ""
}

func reservedFields(v any, path string) []domainerr.FieldViolation {
	switch x := v.(type) {
	case map[string]any:
		var vs []domainerr.FieldViolation
		for k, child := range x {
			p := joinPath(path, k)
			if why := reservedReason(normalizeKey(k)); why != "" {
				vs = append(vs, domainerr.FieldViolation{
					Path:    p,
					Code:    violationReservedName,
					Message: fmt.Sprintf("reserved key %q %s — not a 1.0 LabMITM surface", k, why),
				})
				continue
			}
			vs = append(vs, reservedFields(child, p)...)
		}
		return vs
	case []any:
		var vs []domainerr.FieldViolation
		for i, child := range x {
			vs = append(vs, reservedFields(child, indexPath(path, i))...)
		}
		return vs
	default:
		return nil
	}
}

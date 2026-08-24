package observability

import (
	"net"
	"strings"
)

// forbiddenSet and allowedSet are built once from the catalog tables.
var (
	forbiddenSet = indexStrings(ForbiddenLabels)
	allowedSet   = indexStrings(AllowedLabels)
)

func indexStrings(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		out[strings.ToLower(s)] = struct{}{}
	}
	return out
}

// ForbiddenLabel reports whether key is a prohibited default label
// (subject, address, client IP, actor, host, or free-form error text).
func ForbiddenLabel(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" {
		return false
	}
	if _, ok := forbiddenSet[k]; ok {
		return true
	}
	if strings.Contains(k, "subject") || strings.Contains(k, "client_ip") ||
		strings.Contains(k, "remote_addr") || strings.Contains(k, "password") ||
		strings.Contains(k, "cookie") {
		return true
	}
	return false
}

// AllowedLabel reports whether key is in the global allowlist.
func AllowedLabel(key string) bool {
	_, ok := allowedSet[strings.ToLower(strings.TrimSpace(key))]
	return ok
}

// CheckLabels validates labels against the catalog allowlist for metric.
// Unknown metrics, forbidden keys, and keys not declared on the metric fail.
func CheckLabels(metric string, labels map[string]string) error {
	def, ok := LookupMetric(metric)
	if !ok {
		return labelError("unknown_metric")
	}
	return checkLabelsDef(def, labels)
}

func checkLabelsDef(def MetricDef, labels map[string]string) error {
	allowed := make(map[string]struct{}, len(def.Labels))
	for _, l := range def.Labels {
		allowed[l] = struct{}{}
	}
	for k := range labels {
		if ForbiddenLabel(k) {
			return labelError("forbidden_label")
		}
		if _, ok := allowed[k]; !ok {
			return labelError("unknown_label")
		}
	}
	return nil
}

type labelError string

func (e labelError) Error() string { return string(e) }

// LabelReason is the bounded drop reason for a rejected sample.
func LabelReason(err error) string {
	if err == nil {
		return ""
	}
	if r, ok := err.(labelError); ok {
		return string(r)
	}
	return "invalid"
}

// ProxySessionResult collapses a session outcome to a bounded label.
func ProxySessionResult(result string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "ok", "rejected", "timeout":
		return strings.ToLower(strings.TrimSpace(result))
	default:
		return "rejected"
	}
}

// ProxyRejectReason collapses a reject cause to a bounded label.
func ProxyRejectReason(reason string) string {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "admission", "http2", "socks", "socks_auth", "socks_command", "target_denied", "absolute_https", "origdest":
		return strings.ToLower(strings.TrimSpace(reason))
	default:
		return "admission"
	}
}

// SocksSessionResult collapses a SOCKS handshake outcome to a bounded label.
func SocksSessionResult(result string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "ok", "denied", "auth", "command":
		return strings.ToLower(strings.TrimSpace(result))
	default:
		return "denied"
	}
}

// TLSInterceptResult collapses a handshake outcome to a bounded label.
func TLSInterceptResult(result string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "ok", "mint_fail", "tls_handshake", "upstream_tls", "upstream_verify_fail", "http2_inner":
		return strings.ToLower(strings.TrimSpace(result))
	default:
		return "tls_handshake"
	}
}

// FlowScheme collapses a captured scheme to http or https.
func FlowScheme(scheme string) string {
	if strings.EqualFold(strings.TrimSpace(scheme), "https") {
		return "https"
	}
	return "http"
}

// InterceptedLabel is the bounded intercepted series value.
func InterceptedLabel(ok bool) string {
	if ok {
		return "true"
	}
	return "false"
}

// WSOpcodeLabel collapses a WebSocket opcode to a bounded label.
func WSOpcodeLabel(opcode string) string {
	switch strings.ToLower(strings.TrimSpace(opcode)) {
	case "continuation", "text", "binary", "close", "ping", "pong":
		return strings.ToLower(strings.TrimSpace(opcode))
	default:
		return "other"
	}
}

// GRPCDecodeResult collapses a gRPC decode outcome to a bounded label.
func GRPCDecodeResult(result string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "ok", "malformed", "truncated", "skipped":
		return strings.ToLower(strings.TrimSpace(result))
	default:
		return "skipped"
	}
}

// FlowResult collapses a capture outcome to a bounded label.
func FlowResult(result string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "ok", "rejected", "error", "timeout":
		return strings.ToLower(strings.TrimSpace(result))
	default:
		if result == "" {
			return "ok"
		}
		return "error"
	}
}

// AuthFailureReason collapses an auth failure to a bounded label.
func AuthFailureReason(reason string) string {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "missing", "invalid", "denied":
		return strings.ToLower(strings.TrimSpace(reason))
	default:
		return "invalid"
	}
}

// CodeClass collapses an HTTP status to a bounded class.
func CodeClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

// ClassifyHost maps a request-target host to host_class. Raw Host is
// never a metric label and is omitted from info logs.
func ClassifyHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "unknown"
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return "ip"
	}
	lower := strings.ToLower(host)
	if isLabSuffix(lower) {
		return "lab"
	}
	return "public"
}

func isLabSuffix(host string) bool {
	return host == "lab" ||
		strings.HasSuffix(host, ".lab") ||
		strings.HasSuffix(host, ".lab.test") ||
		strings.Contains(host, ".lab.")
}

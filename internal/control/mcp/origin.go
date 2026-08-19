package mcp

import "github.com/hilather/go-lab-mitmproxy/internal/auth"

// checkOrigin is the shared LabDNS rule (missing allowed; non-http(s) denied).
func checkOrigin(origin string, allowlist []string) error {
	return auth.CheckOrigin(origin, allowlist)
}

func originAllowed(origin string, extra []string) bool {
	return checkOrigin(origin, extra) == nil
}

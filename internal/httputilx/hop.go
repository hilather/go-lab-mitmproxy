package httputilx

import (
	"net/http"
	"strings"
)

// hopByHop names are stripped on both legs when rebuilding origin-form
// requests and client-facing responses. Transfer-Encoding is stripped
// because the stdlib encoder chooses identity or chunked.
var hopByHop = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Proxy-Authorization",
	"Upgrade",
}

// IsWebSocketUpgrade reports Upgrade: websocket with Connection: Upgrade.
func IsWebSocketUpgrade(h http.Header) bool {
	if h == nil {
		return false
	}
	if !headerHasToken(h, "Upgrade", "websocket") {
		return false
	}
	return headerHasToken(h, "Connection", "Upgrade")
}

// StripHopByHop removes hop-by-hop headers, including Connection tokens.
func StripHopByHop(h http.Header) {
	if h == nil {
		return
	}
	for _, v := range h.Values("Connection") {
		for tok := range strings.SplitSeq(v, ",") {
			name := http.CanonicalHeaderKey(strings.TrimSpace(tok))
			if name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

// PrepareRequest strips hop-by-hop headers and Expect: 100-continue.
// WebSocket upgrades keep Upgrade and Connection: Upgrade only.
func PrepareRequest(h http.Header) {
	ws := IsWebSocketUpgrade(h)
	StripHopByHop(h)
	h.Del("Expect")
	if ws {
		h.Set("Upgrade", "websocket")
		h.Set("Connection", "Upgrade")
	}
}

// PrepareResponse strips hop-by-hop headers on the client-facing response.
// On a 101 websocket upgrade it keeps Upgrade and Connection: Upgrade.
func PrepareResponse(h http.Header, websocket bool) {
	StripHopByHop(h)
	if websocket {
		h.Set("Upgrade", "websocket")
		h.Set("Connection", "Upgrade")
	}
}

// CopyHeaders appends src onto dst without sharing the backing arrays.
func CopyHeaders(dst, src http.Header) {
	if dst == nil || src == nil {
		return
	}
	for k, vs := range src {
		dst[k] = append([]string(nil), vs...)
	}
}

func headerHasToken(h http.Header, key, want string) bool {
	want = strings.ToLower(want)
	for _, v := range h.Values(key) {
		for tok := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), want) {
				return true
			}
		}
	}
	return false
}

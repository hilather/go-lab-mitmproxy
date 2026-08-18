package httputilx

import (
	"net/http"
	"testing"
)

func TestStripHopByHop(t *testing.T) {
	h := http.Header{
		"Host":                {"app.lab"},
		"Connection":          {"Keep-Alive, X-Hop"},
		"Keep-Alive":          {"timeout=5"},
		"Proxy-Connection":    {"keep-alive"},
		"Te":                  {"trailers"},
		"Trailer":             {"X-T"},
		"Transfer-Encoding":   {"chunked"},
		"Proxy-Authorization": {"Basic x"},
		"Upgrade":             {"h2c"},
		"X-Hop":               {"1"},
		"X-Keep":              {"yes"},
	}
	StripHopByHop(h)
	for _, name := range []string{
		"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer",
		"Transfer-Encoding", "Proxy-Authorization", "Upgrade", "X-Hop",
	} {
		if _, ok := h[name]; ok {
			t.Fatalf("header %s still present: %v", name, h)
		}
	}
	if got := h.Get("X-Keep"); got != "yes" {
		t.Fatalf("end-to-end header stripped: %v", h)
	}
}

func TestWebSocketKeepsUpgrade(t *testing.T) {
	h := http.Header{
		"Upgrade":    {"websocket"},
		"Connection": {"keep-alive, Upgrade"},
		"Host":       {"app.lab"},
	}
	if !IsWebSocketUpgrade(h) {
		t.Fatal("expected websocket upgrade")
	}
	PrepareRequest(h)
	if h.Get("Upgrade") != "websocket" {
		t.Fatalf("Upgrade=%q", h.Get("Upgrade"))
	}
	if h.Get("Connection") != "Upgrade" {
		t.Fatalf("Connection=%q", h.Get("Connection"))
	}
	if h.Get("Host") != "app.lab" {
		t.Fatalf("Host=%q", h.Get("Host"))
	}
}

func TestUpgradeWithoutConnectionIsHop(t *testing.T) {
	h := http.Header{
		"Upgrade": {"websocket"},
		"Host":    {"app.lab"},
	}
	if IsWebSocketUpgrade(h) {
		t.Fatal("Upgrade without Connection: Upgrade must not be special-cased")
	}
	PrepareRequest(h)
	if h.Get("Upgrade") != "" {
		t.Fatalf("Upgrade kept: %v", h)
	}
}

func TestPrepareRequestStripsExpect(t *testing.T) {
	h := http.Header{"Expect": {"100-continue"}, "X-A": {"1"}}
	PrepareRequest(h)
	if h.Get("Expect") != "" {
		t.Fatalf("Expect kept: %v", h)
	}
	if h.Get("X-A") != "1" {
		t.Fatalf("X-A stripped: %v", h)
	}
}

func TestPrepareResponseWebsocket(t *testing.T) {
	h := http.Header{
		"Upgrade":    {"websocket"},
		"Connection": {"Upgrade"},
		"Date":       {"now"},
	}
	PrepareResponse(h, true)
	if h.Get("Upgrade") != "websocket" || h.Get("Connection") != "Upgrade" {
		t.Fatalf("101 headers: %v", h)
	}
	if h.Get("Date") != "now" {
		t.Fatalf("Date stripped: %v", h)
	}
}

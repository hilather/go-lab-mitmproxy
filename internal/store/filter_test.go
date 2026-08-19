package store

import (
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestMatchFilterProtocolAndVia(t *testing.T) {
	f := &model.Flow{
		Host:     "app.lab",
		Protocol: model.FlowProtocolHTTP2,
		Via:      "http-proxy",
	}
	if !matchFilter(f, model.FlowFilter{Protocol: "H2"}) {
		t.Fatal("protocol is case-insensitive")
	}
	if matchFilter(f, model.FlowFilter{Protocol: model.FlowProtocolHTTP11}) {
		t.Fatal("protocol mismatch")
	}
	if !matchFilter(f, model.FlowFilter{Via: "http-proxy"}) {
		t.Fatal("via exact")
	}
	if matchFilter(f, model.FlowFilter{Via: "HTTP-PROXY"}) {
		t.Fatal("via is case-sensitive")
	}
	if matchFilter(f, model.FlowFilter{Via: "socks5"}) {
		t.Fatal("via mismatch")
	}
}

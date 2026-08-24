package store

import (
	"bytes"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestCloneFlowCopiesHTTP2SOCKSTrailers(t *testing.T) {
	in := &model.Flow{
		Protocol:     model.FlowProtocolHTTP2,
		Via:          "socks5",
		OriginalDest: "10.0.0.1:443",
		HTTP2:        &model.HTTP2Info{StreamID: 7},
		SOCKS:        &model.SOCKSInfo{Version: 5, ATYP: "domain", Dest: "app.lab:443", Command: "connect", BND: "127.0.0.1:54321", User: "lab-socks"},
		WebSocket: &model.WebSocketInfo{
			FrameCount: 1,
			Frames:     []model.WebSocketFrame{{Opcode: "text", Payload: []byte("hi"), Size: 2}},
		},
		GRPC: &model.GRPCInfo{
			ContentType: "application/grpc",
			Messages: []model.GRPCMessage{{
				Length: 2,
				Fields: []model.ProtoField{{Number: 1, WireType: 2, Text: "ab", Nested: []model.ProtoField{{Number: 2, Uint: 9}}}},
			}},
		},
		Request: model.HTTPMessage{
			Headers:  []model.Header{{Name: "Host", Value: "app.lab"}},
			Trailers: []model.Header{{Name: "X-T", Value: "1"}},
			Body:     []byte("req"),
		},
		Response: model.HTTPMessage{
			Trailers: []model.Header{{Name: "X-R", Value: "2"}},
		},
	}
	out := cloneFlow(in)
	in.HTTP2.StreamID = 99
	in.SOCKS.Dest = "mutated"
	in.SOCKS.User = "mutated"
	in.WebSocket.Frames[0].Payload[0] = 'X'
	in.GRPC.Messages[0].Fields[0].Text = "mut"
	in.GRPC.Messages[0].Fields[0].Nested[0].Uint = 1
	in.Request.Trailers[0].Value = "mut"
	in.Response.Trailers[0].Value = "mut"
	in.Request.Body[0] = 'X'
	if out.HTTP2 == nil || out.HTTP2.StreamID != 7 {
		t.Fatalf("http2=%+v", out.HTTP2)
	}
	if out.SOCKS == nil || out.SOCKS.Dest != "app.lab:443" || out.SOCKS.BND != "127.0.0.1:54321" || out.SOCKS.User != "lab-socks" {
		t.Fatalf("socks=%+v", out.SOCKS)
	}
	if out.WebSocket == nil || string(out.WebSocket.Frames[0].Payload) != "hi" {
		t.Fatalf("websocket=%+v", out.WebSocket)
	}
	if out.GRPC == nil || out.GRPC.Messages[0].Fields[0].Text != "ab" || out.GRPC.Messages[0].Fields[0].Nested[0].Uint != 9 {
		t.Fatalf("grpc=%+v", out.GRPC)
	}
	if out.Request.Trailers[0].Value != "1" || out.Response.Trailers[0].Value != "2" {
		t.Fatalf("trailers mutated: %+v %+v", out.Request.Trailers, out.Response.Trailers)
	}
	if !bytes.Equal(out.Request.Body, []byte("req")) {
		t.Fatalf("body=%q", out.Request.Body)
	}
	if out.Via != "socks5" || out.OriginalDest != "10.0.0.1:443" {
		t.Fatalf("meta via=%q dest=%q", out.Via, out.OriginalDest)
	}
}

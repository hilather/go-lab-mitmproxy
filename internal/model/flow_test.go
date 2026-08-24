package model

import "testing"

func TestResidentBytes(t *testing.T) {
	f := &Flow{
		Request: HTTPMessage{
			Headers: []Header{{Name: "Host", Value: "a"}},
			Body:    []byte("req"),
		},
		Response: HTTPMessage{
			Headers: []Header{{Name: "Content-Type", Value: "text/plain"}},
			Body:    []byte("ok"),
		},
	}
	want := int64(len("req") + len("ok") + len("Host") + len("a") + 4 + len("Content-Type") + len("text/plain") + 4)
	if f.ResidentBytes() != want {
		t.Fatalf("got %d want %d", f.ResidentBytes(), want)
	}
	spilled := &Flow{
		Request:  HTTPMessage{Size: 9},
		Response: HTTPMessage{Body: []byte("x")},
	}
	if spilled.ResidentBytes() != 10 {
		t.Fatalf("spilled %d", spilled.ResidentBytes())
	}
	trailers := &Flow{
		Request: HTTPMessage{
			Trailers: []Header{{Name: "X-T", Value: "1"}},
		},
	}
	if trailers.ResidentBytes() != int64(len("X-T")+len("1")+4) {
		t.Fatalf("trailers %d", trailers.ResidentBytes())
	}
}

func TestResidentBytesWebSocket(t *testing.T) {
	f := &Flow{
		WebSocket: &WebSocketInfo{
			FrameCount: 2,
			Frames: []WebSocketFrame{
				{Payload: []byte("hi"), Size: 2},
				{Size: 5},
			},
		},
	}
	want := int64(WSFrameOverhead + 2 + WSFrameOverhead + 5)
	if f.ResidentBytes() != want {
		t.Fatalf("got %d want %d", f.ResidentBytes(), want)
	}
}

func TestFlowPath(t *testing.T) {
	f := &Flow{URL: "https://app.lab.test/login?x=1"}
	if f.Path() != "/login" {
		t.Fatalf("path=%q", f.Path())
	}
	if (&Flow{URL: "http://h"}).Path() != "/" {
		t.Fatal("empty path")
	}
}

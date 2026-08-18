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

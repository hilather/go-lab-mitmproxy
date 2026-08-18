package store

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestSubscribeInsertDeleteWipe(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	ch, cancel := s.Subscribe(8)
	defer cancel()
	res, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/", 200, []byte("body")))
	if err != nil {
		t.Fatal(err)
	}
	got := <-ch
	if got.Kind != EventInserted || got.ID != res.ID || got.Gen == 0 {
		t.Fatalf("insert event %+v", got)
	}
	if err := s.Delete(res.ID); err != nil {
		t.Fatal(err)
	}
	got = <-ch
	if got.Kind != EventDeleted || got.ID != res.ID {
		t.Fatalf("delete event %+v", got)
	}
	s.Wipe()
	got = <-ch
	if got.Kind != EventWiped || got.Gen == 0 {
		t.Fatalf("wipe event %+v", got)
	}
}

func TestSubscribePausedInsert(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	ch, cancel := s.Subscribe(4)
	defer cancel()
	f := sampleFlow("GET", "http://h/", 0, nil)
	f.State = model.FlowStatePaused
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	got := <-ch
	if got.Kind != EventPaused || got.ID != res.ID {
		t.Fatalf("paused insert event %+v", got)
	}
}

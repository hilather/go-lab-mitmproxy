package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRingAppendListGet(t *testing.T) {
	r := NewRing(3)
	e1 := r.Append(Event{Reason: "one", Time: time.Unix(1, 0).UTC()})
	e2 := r.Append(Event{Reason: "two"})
	e3 := r.Append(Event{Reason: "three"})
	if e1.ID != "aud-1" || e2.ID != "aud-2" || e3.ID != "aud-3" {
		t.Fatalf("ids %s %s %s", e1.ID, e2.ID, e3.ID)
	}
	got := r.List(10)
	if len(got) != 3 || got[0].ID != "aud-3" || got[2].ID != "aud-1" {
		t.Fatalf("list=%+v", got)
	}
	ev, ok := r.Get("aud-2")
	if !ok || ev.Reason != "two" {
		t.Fatalf("get=%+v ok=%v", ev, ok)
	}
	if _, ok := r.Get("missing"); ok {
		t.Fatal("missing")
	}
}

func TestRingEvictsOldest(t *testing.T) {
	r := NewRing(2)
	r.Append(Event{Reason: "a"})
	r.Append(Event{Reason: "b"})
	r.Append(Event{Reason: "c"})
	if r.Len() != 2 {
		t.Fatalf("len=%d", r.Len())
	}
	if _, ok := r.Get("aud-1"); ok {
		t.Fatal("oldest should fall off")
	}
	got := r.List(0)
	if len(got) != 2 || got[0].Reason != "c" || got[1].Reason != "b" {
		t.Fatalf("list=%+v", got)
	}
}

func TestFanoutRedactsAndSwallowsHookError(t *testing.T) {
	f := NewFanout(8, SinkFunc(func(context.Context, Event) error {
		return errors.New("hook down")
	}))
	ev := f.Record(context.Background(), Event{
		Reason: "Bearer hunter2",
		Diff: []RedactedEntry{{
			Path:   "spec.management.auth.tokens[0].token",
			Op:     "replace",
			Before: []byte(`"old"`),
			After:  []byte(`"new"`),
		}},
	})
	if ev.Reason != "[redacted]" {
		t.Fatalf("reason=%q", ev.Reason)
	}
	if string(ev.Diff[0].After) != `"[redacted]"` {
		t.Fatalf("diff after=%s", ev.Diff[0].After)
	}
	if f.DeliveryFailures() != 1 {
		t.Fatalf("hook errs=%d", f.DeliveryFailures())
	}
	listed := f.List(1)
	if len(listed) != 1 || listed[0].ID != ev.ID {
		t.Fatalf("list=%+v", listed)
	}
}

func TestRedactNeverLogsPrivateKey(t *testing.T) {
	pem := "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIOsecret\n-----END EC PRIVATE KEY-----"
	f := NewFanout(4, nil)
	ev := f.Record(context.Background(), Event{
		Reason: "rotated CA " + pem,
		Diff: []RedactedEntry{{
			Path:   "spec.tls.ca",
			Op:     "replace",
			Before: []byte(`"` + pem + `"`),
			After:  []byte(`{"pem":"` + pem + `"}`),
		}},
	})
	if strings.Contains(ev.Reason, "BEGIN") && strings.Contains(ev.Reason, "PRIVATE") {
		t.Fatalf("reason leaked PEM: %q", ev.Reason)
	}
	if ev.Reason != "[redacted]" {
		t.Fatalf("reason=%q", ev.Reason)
	}
	blob := string(ev.Diff[0].Before) + string(ev.Diff[0].After)
	if strings.Contains(blob, "BEGIN") && strings.Contains(blob, "PRIVATE") {
		t.Fatalf("diff leaked PEM: %s", blob)
	}
}

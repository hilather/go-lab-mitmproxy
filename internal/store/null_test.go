package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestNullInsertAndEpoch(t *testing.T) {
	n := NewNull()
	if n.Epoch() != 1 {
		t.Fatalf("epoch=%d", n.Epoch())
	}
	res, err := n.Insert(context.Background(), n.Epoch(), sampleFlow("GET", "http://h/", 200, []byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.ID, "null-") {
		t.Fatalf("id=%q", res.ID)
	}
	old := n.Epoch()
	n.Wipe()
	if n.Epoch() != 2 {
		t.Fatalf("epoch after wipe=%d", n.Epoch())
	}
	_, err = n.Insert(context.Background(), old, sampleFlow("GET", "http://h/", 200, []byte("y")))
	if !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("stale insert err=%v", err)
	}
}

func TestNullInsertCanceled(t *testing.T) {
	n := NewNull()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := n.Insert(ctx, n.Epoch(), &model.Flow{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestNullInsertNilFlow(t *testing.T) {
	n := NewNull()
	_, err := n.Insert(context.Background(), n.Epoch(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSentinelErrors(t *testing.T) {
	if ErrFull == nil || ErrStaleEpoch == nil {
		t.Fatal("sentinels")
	}
	if errors.Is(ErrFull, ErrStaleEpoch) {
		t.Fatal("sentinels must differ")
	}
	if ErrTooLarge == nil || ErrNotFound == nil || ErrSpill == nil || ErrBreakpointInactive == nil || ErrDropped == nil {
		t.Fatal("STORE-001 sentinels")
	}
}

//go:build !linux

package proxy

import (
	"context"
	"testing"
	"time"
)

func TestOrigDestStartFailsClosed(t *testing.T) {
	spec := loadSpec(t)
	spec.Listeners.OriginalDestination.Enabled = true
	spec.Listeners.OriginalDestination.Address = "127.0.0.1:0"
	s, err := New(Options{Address: "127.0.0.1:0", Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	if err := s.Start(); err == nil {
		t.Fatal("enabled orig-dest must fail closed off linux")
	}
	if s.Addr() != nil || s.OrigDestAddr() != nil {
		t.Fatal("Start must bind nothing")
	}
}

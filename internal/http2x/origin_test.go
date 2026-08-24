package http2x

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestDialTLSNil(t *testing.T) {
	client, server := h2TLSPair(t)
	go (&http2.Server{}).ServeConn(server, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "origin")
		}),
	})
	tr, err := NewOriginTransport(client)
	if err != nil {
		t.Fatal(err)
	}
	if tr.DialTLS != nil { //nolint:staticcheck
		t.Fatal("DialTLS must stay nil")
	}
	if tr.DialTLSContext == nil {
		t.Fatal("DialTLSContext must refuse redial, not fall through to tls.Dial")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := tr.DialTLSContext(ctx, "tcp", "example.com:443", &tls.Config{MinVersion: tls.VersionTLS12})
	if c != nil || !errors.Is(err, ErrRefuseRedial) {
		t.Fatalf("DialTLSContext=%v err=%v", c, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/o", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "origin" {
		t.Fatalf("body %q", body)
	}
}

func TestPinnedPoolRefusesRedialAfterDead(t *testing.T) {
	p := &pinnedPool{}
	_, err := p.GetClientConn(&http.Request{}, "app.lab:443")
	if err != ErrRefuseRedial {
		t.Fatalf("err=%v", err)
	}
	p.MarkDead(nil)
	_, err = p.GetClientConn(&http.Request{}, "app.lab:443")
	if err != ErrRefuseRedial {
		t.Fatalf("err=%v", err)
	}
}

func TestOriginTransportRoundTripAfterDeadRefusesRedial(t *testing.T) {
	client, server := h2TLSPair(t)
	go (&http2.Server{}).ServeConn(server, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "origin")
		}),
	})
	tr, err := NewOriginTransport(client)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/o", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	_ = client.Close()
	pool, ok := tr.ConnPool.(*pinnedPool)
	if !ok {
		t.Fatal("expected pinnedPool")
	}
	pool.MarkDead(pool.cc)
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/o2", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tr.RoundTrip(req2)
	if !errors.Is(err, ErrRefuseRedial) {
		t.Fatalf("second open err=%v", err)
	}
}

func TestOriginTransportMultiplexTwoStreams(t *testing.T) {
	client, server := h2TLSPair(t)
	var inflight atomic.Int32
	var max atomic.Int32
	go (&http2.Server{}).ServeConn(server, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := inflight.Add(1)
			defer inflight.Add(-1)
			for {
				old := max.Load()
				if n <= old || max.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(80 * time.Millisecond)
			_, _ = io.WriteString(w, r.URL.Path)
		}),
	})
	tr, err := NewOriginTransport(client)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	got := make(chan string, 2)
	for _, path := range []string{"/a", "/b"} {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab"+path, nil)
			if err != nil {
				t.Error(err)
				return
			}
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			got <- string(body)
		}(path)
	}
	wg.Wait()
	close(got)
	bodies := map[string]bool{}
	for b := range got {
		bodies[b] = true
	}
	if !bodies["/a"] || !bodies["/b"] {
		t.Fatalf("bodies %#v", bodies)
	}
	if max.Load() < 2 {
		t.Fatalf("want multiplex max>=2 got %d", max.Load())
	}
}

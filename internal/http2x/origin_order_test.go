package http2x

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// A caller can lose the writer lock even if it reached the writer first.
// Opening stream IDs must follow the order HEADERS reach the wire, rather
// than the order RoundTrip goroutines arrive before taking that lock.
func TestOriginConnOpeningHeadersFollowStreamIDOrder(t *testing.T) {
	var wire bytes.Buffer
	var encoded bytes.Buffer
	oc := &OriginConn{
		fr:      http2.NewFramer(&wire, nil),
		enc:     hpack.NewEncoder(&encoded),
		encBuf:  &encoded,
		out:     newOutFlow(),
		inbound: newInFlow(),
		nextID:  1,
		streams: make(map[uint32]*originStream),
		pushes:  make(map[uint32]*pushStream),
	}
	firstWaiting := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
	t.Cleanup(release)
	var writers atomic.Int32
	var writeMu sync.Mutex
	oc.write = func(fn func() error) error {
		if writers.Add(1) == 1 {
			close(firstWaiting)
			<-releaseFirst
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := fn(); err != nil {
			return err
		}
		// Complete each opened request without a reader goroutine. The
		// assertion below independently decodes the outgoing frame IDs.
		oc.mu.Lock()
		defer oc.mu.Unlock()
		for _, st := range oc.streams {
			if !st.gotResp.Swap(true) {
				st.closed.Store(true)
				_ = st.body.Close()
				st.hdr <- []hpack.HeaderField{{Name: ":status", Value: "200"}}
			}
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := func(path string) <-chan error {
		done := make(chan error, 1)
		go func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab"+path, nil)
			if err != nil {
				done <- err
				return
			}
			resp, err := oc.RoundTrip(req)
			if err == nil {
				_, err = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
			done <- err
		}()
		return done
	}
	first := request("/first")
	select {
	case <-firstWaiting:
	case <-ctx.Done():
		t.Fatal("first request never reached the writer")
	}
	second := request("/second")
	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("second request cannot write while first waits for the writer lock")
	}
	release()
	select {
	case err := <-first:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("first request did not finish after releasing the writer")
	}
	fr := http2.NewFramer(nil, bytes.NewReader(wire.Bytes()))
	for _, want := range []uint32{1, 3} {
		frame, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		headers, ok := frame.(*http2.HeadersFrame)
		if !ok || headers.StreamID != want {
			t.Fatalf("opening HEADERS must use increasing stream IDs: want %d, got %v", want, frame)
		}
	}
	if _, err := fr.ReadFrame(); err != io.EOF {
		t.Fatalf("unexpected additional frame: %v", err)
	}
}

// GOAWAY or connection failure can close the origin while another writer
// remains blocked. A later request must refuse immediately, without joining
// that writer queue; the check inside the writer still guards closure after
// this preflight check.
func TestOriginConnClosedRefusesBeforeWaitingForWriter(t *testing.T) {
	for _, closedErr := range []error{nil, io.EOF} {
		t.Run(fmt.Sprint(closedErr), func(t *testing.T) {
			writerCalled := make(chan struct{})
			releaseWriter := make(chan struct{})
			oc := &OriginConn{closed: true, err: closedErr}
			oc.write = func(fn func() error) error {
				close(writerCalled)
				<-releaseWriter
				return fn()
			}
			t.Cleanup(func() { close(releaseWriter) })
			done := make(chan error, 1)
			go func() {
				req, err := http.NewRequest(http.MethodGet, "https://app.lab/closed", nil)
				if err == nil {
					_, err = oc.RoundTrip(req)
				}
				done <- err
			}()
			select {
			case err := <-done:
				want := closedErr
				if want == nil {
					want = ErrRefuseRedial
				}
				if !errors.Is(err, want) {
					t.Fatalf("closed origin error: got %v, want %v", err, want)
				}
			case <-writerCalled:
				t.Fatal("closed origin request waited for the occupied writer")
			case <-time.After(5 * time.Second):
				t.Fatal("closed origin request did not finish")
			}
		})
	}
}

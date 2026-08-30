package http2x

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestOriginConnPOSTBodyZeroContentLength(t *testing.T) {
	client, server := h2TLSPair(t)
	got := make(chan string, 1)
	go (&http2.Server{}).ServeConn(server, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			got <- string(body)
			_, _ = io.WriteString(w, "echo:"+string(body))
		}),
	})
	oc, err := NewOriginConn(client, OriginOpts{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.lab/echo", io.NopCloser(strings.NewReader("hello")))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = 0 // same zero-value reconstructH2Request used to leave
	resp, err := oc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "echo:hello" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	select {
	case saw := <-got:
		if saw != "hello" {
			t.Fatalf("origin body %q", saw)
		}
	case <-ctx.Done():
		t.Fatal("origin never saw POST DATA")
	}
}

func TestRequestHasBodyZeroContentLength(t *testing.T) {
	if requestHasBody(&http.Request{Method: http.MethodPost, Body: io.NopCloser(strings.NewReader("x")), ContentLength: 0}) != true {
		t.Fatal("ContentLength 0 + Body must be a body (h2 POST / gRPC)")
	}
	if requestHasBody(&http.Request{Method: http.MethodGet, Body: http.NoBody}) {
		t.Fatal("NoBody is not a body")
	}
	if requestHasBody(&http.Request{Method: http.MethodGet}) {
		t.Fatal("nil Body is not a body")
	}
}

func TestOriginConnRoundTrip(t *testing.T) {
	client, server := h2TLSPair(t)
	go (&http2.Server{}).ServeConn(server, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "origin")
		}),
	})
	oc, err := NewOriginConn(client, OriginOpts{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/o", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := oc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "origin" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

func TestOriginConnMultiplexTwoStreams(t *testing.T) {
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
	oc, err := NewOriginConn(client, OriginOpts{})
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
			resp, err := oc.RoundTrip(req)
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

func TestOriginConnRoundTripResponseTrailers(t *testing.T) {
	client, server := h2TLSPair(t)
	go (&http2.Server{}).ServeConn(server, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "proto")
			w.Header().Set("Grpc-Status", "0")
			w.Header().Set("Grpc-Message", "ok")
		}),
	})
	oc, err := NewOriginConn(client, OriginOpts{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.lab/svc/Echo", strings.NewReader("in"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := oc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "proto" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("Grpc-Status trailer %q (origin-h2 must surface trailing HEADERS)", got)
	}
	if got := resp.Trailer.Get("Grpc-Message"); got != "ok" {
		t.Fatalf("Grpc-Message trailer %q", got)
	}
}

func TestOriginConnSkips1xxThenForwardsTrailers(t *testing.T) {
	client, server := h2TLSPair(t)
	go writeInformationalThenTrailers(t, server)
	oc, err := NewOriginConn(client, OriginOpts{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/early", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := oc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "final" {
		t.Fatalf("status=%d body=%q (1xx must not become the response)", resp.StatusCode, body)
	}
	if got := resp.Trailer.Get("x-checksum"); got != "abc" {
		t.Fatalf("trailer %q", got)
	}
}

func TestOriginConnEnablePushSetting(t *testing.T) {
	t.Parallel()
	for _, capture := range []bool{false, true} {
		capture := capture
		t.Run(map[bool]string{false: "off", true: "on"}[capture], func(t *testing.T) {
			client, server := h2TLSPair(t)
			got := make(chan uint32, 1)
			go func() {
				preface := make([]byte, len(http2.ClientPreface))
				if _, err := io.ReadFull(server, preface); err != nil {
					t.Error(err)
					return
				}
				fr := http2.NewFramer(server, server)
				deadline := time.Now().Add(3 * time.Second)
				for time.Now().Before(deadline) {
					_ = server.SetDeadline(time.Now().Add(2 * time.Second))
					f, err := fr.ReadFrame()
					if err != nil {
						t.Error(err)
						return
					}
					sf, ok := f.(*http2.SettingsFrame)
					if !ok || sf.IsAck() {
						continue
					}
					var enable uint32
					_ = sf.ForeachSetting(func(s http2.Setting) error {
						if s.ID == http2.SettingEnablePush {
							enable = s.Val
						}
						return nil
					})
					got <- enable
					_ = fr.WriteSettings()
					return
				}
			}()
			_, err := NewOriginConn(client, OriginOpts{CapturePush: capture})
			if err != nil {
				t.Fatal(err)
			}
			select {
			case v := <-got:
				want := uint32(0)
				if capture {
					want = 1
				}
				if v != want {
					t.Fatalf("ENABLE_PUSH=%d want %d", v, want)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("no client SETTINGS")
			}
		})
	}
}

func TestOriginConnCapturesPushPromise(t *testing.T) {
	client, server := h2TLSPair(t)
	pushed := make(chan Pushed, 1)
	go pushOrigin(t, server, true)
	oc, err := NewOriginConn(client, OriginOpts{
		CapturePush: true,
		OnPush:      func(p Pushed) { pushed <- p },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := oc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "parent-body" {
		t.Fatalf("parent status=%d body=%q", resp.StatusCode, body)
	}
	select {
	case p := <-pushed:
		if !p.ResponseTruncated && string(p.ResponseBody) != "pushed-body" {
			t.Fatalf("push body %q", p.ResponseBody)
		}
		if p.PromisedID != 2 || p.ParentStreamID != 1 || p.Path != "/style.css" || p.Method != http.MethodGet {
			t.Fatalf("push %+v", p)
		}
		if p.Status != http.StatusOK {
			t.Fatalf("push status %d", p.Status)
		}
	case <-ctx.Done():
		t.Fatal("push not captured")
	}
}

func TestOriginConnRSTPushWhenCaptureOff(t *testing.T) {
	client, server := h2TLSPair(t)
	rst := make(chan struct{}, 1)
	gotRST := make(chan http2.ErrCode, 1)
	go pushOriginRST(t, server, gotRST)
	oc, err := NewOriginConn(client, OriginOpts{
		CapturePush: false,
		OnPush: func(Pushed) {
			t.Error("OnPush must not fire when capturePush is false")
		},
		OnRST: func() { rst <- struct{}{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := oc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "parent-body" {
		t.Fatalf("parent body %q", body)
	}
	select {
	case <-rst:
	case <-ctx.Done():
		t.Fatal("OnRST not called")
	}
	select {
	case code := <-gotRST:
		if code != http2.ErrCodeCancel {
			t.Fatalf("RST code %v", code)
		}
	case <-ctx.Done():
		t.Fatal("origin did not see RST of promised id")
	}
}

func TestOriginConnPushDATAEndStreamCreditsConnWindow(t *testing.T) {
	client, server := h2TLSPair(t)
	pushed := make(chan Pushed, 1)
	payload := bytes.Repeat([]byte("p"), 16*1024)
	go func() {
		writePushOriginWithBody(t, server, payload, len(payload), nil)
	}()
	oc, err := NewOriginConn(client, OriginOpts{
		CapturePush: true,
		OnPush:      func(p Pushed) { pushed <- p },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := oc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "parent-body" {
		t.Fatalf("parent body %q (conn window not restored after push END_STREAM)", body)
	}
	select {
	case p := <-pushed:
		if !bytes.Equal(p.ResponseBody, payload) {
			t.Fatalf("push len=%d", len(p.ResponseBody))
		}
	case <-ctx.Done():
		t.Fatal("push not captured")
	}
}

func TestOriginConnPushTruncatingFrameCreditsConnWindow(t *testing.T) {
	client, server := h2TLSPair(t)
	pushed := make(chan Pushed, 1)
	payload := bytes.Repeat([]byte("t"), 64)
	go func() {
		writePushOriginWithBody(t, server, payload, len(payload), nil)
	}()
	oc, err := NewOriginConn(client, OriginOpts{
		CapturePush: true,
		MaxBody:     8,
		OnPush:      func(p Pushed) { pushed <- p },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := oc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "parent-body" {
		t.Fatalf("parent body %q (truncating push DATA did not credit conn window)", body)
	}
	select {
	case p := <-pushed:
		if !p.ResponseTruncated || len(p.ResponseBody) != 8 {
			t.Fatalf("trunc %+v len=%d", p.ResponseTruncated, len(p.ResponseBody))
		}
	case <-ctx.Done():
		t.Fatal("truncated push not captured")
	}
}

func TestDecodeHPACKClosesHeaderBlock(t *testing.T) {
	dec := hpack.NewDecoder(4096, nil)
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	if err := enc.WriteField(hpack.HeaderField{Name: "x-foo", Value: "bar"}); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeHPACK(dec, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	enc = hpack.NewEncoder(&buf)
	enc.SetMaxDynamicTableSize(1024)
	if err := enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"}); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeHPACK(dec, buf.Bytes()); err != nil {
		t.Fatalf("dynamic table size update after Close must succeed: %v", err)
	}
}

func TestDecodeHPACKTruncatedBlockErrors(t *testing.T) {
	dec := hpack.NewDecoder(4096, nil)
	if _, err := decodeHPACK(dec, []byte{0x7f}); err == nil {
		t.Fatal("truncated header block must error on Close")
	}
}

func TestOriginConnPushHeaderBlockCapped(t *testing.T) {
	client, server := h2TLSPair(t)
	go func() {
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(server, preface); err != nil {
			return
		}
		fr := http2.NewFramer(server, server)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		_ = fr.WriteSettings()
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					_ = fr.WriteSettingsAck()
				}
			case *http2.MetaHeadersFrame:
				if f.StreamID != 1 {
					continue
				}
				chunk := bytes.Repeat([]byte{0}, 8192)
				if err := fr.WritePushPromise(http2.PushPromiseParam{
					StreamID: 1, PromiseID: 2, BlockFragment: chunk, EndHeaders: false,
				}); err != nil {
					return
				}
				sent := len(chunk)
				for sent <= maxPushHeaderBlock {
					last := sent+len(chunk) > maxPushHeaderBlock
					if err := fr.WriteContinuation(1, last, chunk); err != nil {
						return
					}
					sent += len(chunk)
					if last {
						return
					}
				}
			}
		}
	}()
	oc, err := NewOriginConn(client, OriginOpts{CapturePush: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = oc.RoundTrip(req)
	if err == nil {
		t.Fatal("oversized PUSH_PROMISE CONTINUATION must fail the origin hop")
	}
}

func TestOriginConnDoesNotForwardPush(t *testing.T) {
	client, server := h2TLSPair(t)
	var onPush atomic.Int32
	go pushOrigin(t, server, true)
	oc, err := NewOriginConn(client, OriginOpts{
		CapturePush: true,
		OnPush:      func(Pushed) { onPush.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := oc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "parent-body" {
		t.Fatalf("parent must not include push body, got %q", body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for onPush.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if onPush.Load() != 1 {
		t.Fatalf("OnPush=%d", onPush.Load())
	}
}

func pushOrigin(t *testing.T, server io.ReadWriter, _ bool) {
	t.Helper()
	writePushOrigin(t, server, nil)
}

func pushOriginRST(t *testing.T, server io.ReadWriter, gotRST chan<- http2.ErrCode) {
	t.Helper()
	writePushOrigin(t, server, gotRST)
}

func writePushOrigin(t *testing.T, server io.ReadWriter, gotRST chan<- http2.ErrCode) {
	t.Helper()
	writePushOriginWithBody(t, server, []byte("pushed-body"), 0, gotRST)
}

func writePushOriginWithBody(t *testing.T, server io.ReadWriter, pushBody []byte, waitConnCredit int, gotRST chan<- http2.ErrCode) {
	t.Helper()
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(server, preface); err != nil {
		t.Error(err)
		return
	}
	fr := http2.NewFramer(server, server)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		t.Error(err)
		return
	}
	_ = fr.WriteWindowUpdate(0, uint32(initialWindow-65535))
	deadline := time.Now().Add(8 * time.Second)
	sawGET := false
	needCredit := 0
	credited := 0
	sendParent := func() bool {
		parent := encodeFields(t, []hpack.HeaderField{{Name: ":status", Value: "200"}})
		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: parent,
			EndHeaders:    true,
		}); err != nil {
			t.Error(err)
			return false
		}
		if err := fr.WriteData(1, true, []byte("parent-body")); err != nil {
			t.Error(err)
			return false
		}
		return true
	}
	for time.Now().Before(deadline) {
		if sc, ok := server.(interface{ SetDeadline(time.Time) error }); ok {
			_ = sc.SetDeadline(time.Now().Add(3 * time.Second))
		}
		f, err := fr.ReadFrame()
		if err != nil {
			if !sawGET {
				t.Error(err)
			}
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.WindowUpdateFrame:
			if needCredit > 0 && f.StreamID == 0 {
				credited += int(f.Increment)
				if credited >= needCredit {
					needCredit = 0
					if !sendParent() {
						return
					}
					if gotRST == nil {
						return
					}
				}
			}
		case *http2.MetaHeadersFrame:
			if f.StreamID != 1 {
				continue
			}
			sawGET = true
			block := encodeFields(t, []hpack.HeaderField{
				{Name: ":method", Value: http.MethodGet},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "app.lab"},
				{Name: ":path", Value: "/style.css"},
			})
			if err := fr.WritePushPromise(http2.PushPromiseParam{
				StreamID:      1,
				PromiseID:     2,
				BlockFragment: block,
				EndHeaders:    true,
			}); err != nil {
				t.Error(err)
				return
			}
			resp := encodeFields(t, []hpack.HeaderField{
				{Name: ":status", Value: "200"},
				{Name: "content-type", Value: "text/css"},
			})
			if err := fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      2,
				BlockFragment: resp,
				EndHeaders:    true,
			}); err != nil {
				t.Error(err)
				return
			}
			if err := fr.WriteData(2, true, pushBody); err != nil {
				t.Error(err)
				return
			}
			if waitConnCredit > 0 {
				needCredit = waitConnCredit
				continue
			}
			if !sendParent() {
				return
			}
			if gotRST == nil {
				return
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == 2 && gotRST != nil {
				select {
				case gotRST <- f.ErrCode:
				default:
				}
				return
			}
		}
	}
}

func writeInformationalThenTrailers(t *testing.T, server io.ReadWriter) {
	t.Helper()
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(server, preface); err != nil {
		t.Error(err)
		return
	}
	fr := http2.NewFramer(server, server)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		t.Error(err)
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sc, ok := server.(interface{ SetDeadline(time.Time) error }); ok {
			_ = sc.SetDeadline(time.Now().Add(2 * time.Second))
		}
		f, err := fr.ReadFrame()
		if err != nil {
			t.Error(err)
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.MetaHeadersFrame:
			if f.StreamID != 1 {
				continue
			}
			hint := encodeFields(t, []hpack.HeaderField{{Name: ":status", Value: "103"}})
			if err := fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: 1, BlockFragment: hint, EndHeaders: true,
			}); err != nil {
				t.Error(err)
				return
			}
			final := encodeFields(t, []hpack.HeaderField{{Name: ":status", Value: "200"}})
			if err := fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: 1, BlockFragment: final, EndHeaders: true,
			}); err != nil {
				t.Error(err)
				return
			}
			if err := fr.WriteData(1, false, []byte("final")); err != nil {
				t.Error(err)
				return
			}
			tr := encodeFields(t, []hpack.HeaderField{{Name: "x-checksum", Value: "abc"}})
			if err := fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: 1, BlockFragment: tr, EndHeaders: true, EndStream: true,
			}); err != nil {
				t.Error(err)
			}
			return
		}
	}
}

func encodeFields(t *testing.T, fields []hpack.HeaderField) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, hf := range fields {
		if err := enc.WriteField(hf); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

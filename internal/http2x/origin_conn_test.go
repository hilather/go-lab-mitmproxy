package http2x

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

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
	deadline := time.Now().Add(5 * time.Second)
	sawGET := false
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
			if err := fr.WriteData(2, true, []byte("pushed-body")); err != nil {
				t.Error(err)
				return
			}
			parent := encodeFields(t, []hpack.HeaderField{{Name: ":status", Value: "200"}})
			if err := fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      1,
				BlockFragment: parent,
				EndHeaders:    true,
			}); err != nil {
				t.Error(err)
				return
			}
			if err := fr.WriteData(1, true, []byte("parent-body")); err != nil {
				t.Error(err)
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

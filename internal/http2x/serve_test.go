package http2x

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestServeClientEnablePushZero(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		_ = ServeClient(ctx, server, func(context.Context, Stream) (*http.Response, []model.Header, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil, nil
		})
	}()
	if _, err := client.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(client, client)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		sf, ok := f.(*http2.SettingsFrame)
		if !ok || sf.IsAck() {
			continue
		}
		var enable *uint32
		_ = sf.ForeachSetting(func(s http2.Setting) error {
			if s.ID == http2.SettingEnablePush {
				v := s.Val
				enable = &v
			}
			return nil
		})
		if enable == nil || *enable != 0 {
			t.Fatalf("inner EnablePush=%v (must stay 0)", enable)
		}
		return
	}
	t.Fatal("no server SETTINGS")
}

func TestServeClientGET(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got := make(chan Stream, 1)
	go func() {
		_ = ServeClient(ctx, server, func(ctx context.Context, in Stream) (*http.Response, []model.Header, error) {
			body, _ := io.ReadAll(in.Body)
			inCopy := in
			inCopy.Body = nil
			if len(body) != 0 {
				t.Errorf("unexpected body %q", body)
			}
			got <- inCopy
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil, nil
		})
	}()

	cc, err := (&http2.Transport{}).NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/login?x=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "labmitm-test")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("body %q", body)
	}
	select {
	case in := <-got:
		if in.ID != 1 {
			t.Fatalf("stream id %d", in.ID)
		}
		if in.Method != http.MethodGet || in.Scheme != "https" || in.Authority != "app.lab" || in.Path != "/login?x=1" {
			t.Fatalf("denorm %+v", in)
		}
		if len(in.Pseudos) < 4 {
			t.Fatalf("pseudos %+v", in.Pseudos)
		}
		if in.Pseudos[0].Name != ":method" || in.Pseudos[0].Value != "GET" {
			t.Fatalf("first pseudo %+v", in.Pseudos[0])
		}
		foundUA := false
		for _, h := range in.Headers {
			if strings.EqualFold(h.Name, "user-agent") && h.Value == "labmitm-test" {
				foundUA = true
			}
		}
		if !foundUA {
			t.Fatalf("headers %+v", in.Headers)
		}
	case <-ctx.Done():
		t.Fatal("handler not invoked")
	}
}

func TestServeClientKeepsRequestBodyAfterHandlerReturns(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gotBody := make(chan string, 1)
	go func() {
		_ = ServeClient(ctx, server, func(ctx context.Context, in Stream) (*http.Response, []model.Header, error) {
			go func() {
				body, _ := io.ReadAll(in.Body)
				gotBody <- string(body)
			}()
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil, nil
		})
	}()
	if _, err := client.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(client, client)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	ackSettings(t, fr)
	var hdr bytes.Buffer
	enc := hpack.NewEncoder(&hdr)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodPost},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "app.lab"},
		{Name: ":path", Value: "/upload"},
	} {
		if err := enc.WriteField(hf); err != nil {
			t.Fatal(err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hdr.Bytes(),
		EndHeaders:    true,
	}); err != nil {
		t.Fatal(err)
	}
	if !readH2Status(t, fr, 1, "200") {
		t.Fatal("want :status=200 before trailing DATA")
	}
	if err := fr.WriteData(1, false, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteData(1, true, []byte("world")); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-gotBody:
		if body != "helloworld" {
			t.Fatalf("body %q (handler return must not close an open upload)", body)
		}
	case <-ctx.Done():
		t.Fatal("request body never drained after early response")
	}
}

func TestServeClientSilentCloseRSTCancel(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		_ = ServeClient(ctx, server, func(ctx context.Context, in Stream) (*http.Response, []model.Header, error) {
			return nil, nil, ErrSilentClose
		})
	}()
	cc, err := (&http2.Transport{}).NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/silent", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cc.RoundTrip(req)
	if err == nil {
		t.Fatal("expected RST CANCEL, not HEADERS")
	}
	if ctx.Err() != nil {
		t.Fatalf("timed out waiting for RST: %v", err)
	}
	var se http2.StreamError
	if errors.As(err, &se) && se.Code != http2.ErrCodeCancel {
		t.Fatalf("RST code %v want CANCEL", se.Code)
	}
}

func TestResetCancelIgnoresPlainConn(t *testing.T) {
	if ResetCancel(nil) {
		t.Fatal("nil")
	}
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close() }()
	if ResetCancel(c1) {
		t.Fatal("plain pipe is not framedStreamConn")
	}
}

func TestServeClientInnerCONNECTRST(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		_ = ServeClient(ctx, server, func(ctx context.Context, in Stream) (*http.Response, []model.Header, error) {
			return nil, nil, ErrInnerCONNECT
		})
	}()
	cc, err := (&http2.Transport{}).NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cc.RoundTrip(req)
	if err == nil {
		t.Fatal("expected RST")
	}
	if ctx.Err() != nil {
		t.Fatalf("timed out waiting for RST: %v", err)
	}
}

func TestServeClientPOSTBody(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		_ = ServeClient(ctx, server, func(ctx context.Context, in Stream) (*http.Response, []model.Header, error) {
			body, err := io.ReadAll(in.Body)
			if err != nil {
				return nil, nil, err
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("got:" + string(body))),
			}, nil, nil
		})
	}()
	cc, err := (&http2.Transport{}).NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.lab/echo", strings.NewReader("hi"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "got:hi" {
		t.Fatalf("body %q", body)
	}
}

func TestServeClientTrailersThenGET(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := make(chan Stream, 2)
	go func() {
		_ = ServeClient(ctx, server, func(ctx context.Context, in Stream) (*http.Response, []model.Header, error) {
			_, _ = io.Copy(io.Discard, in.Body)
			inCopy := in
			inCopy.Body = nil
			got <- inCopy
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil, nil
		})
	}()
	cc, err := (&http2.Transport{}).NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()

	post, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.lab/one", strings.NewReader("hi"))
	if err != nil {
		t.Fatal(err)
	}
	post.Trailer = http.Header{"X-Trailer": []string{"end"}}
	resp, err := cc.RoundTrip(post)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	get, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/two", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = cc.RoundTrip(get)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	var first, second Stream
	select {
	case first = <-got:
	case <-ctx.Done():
		t.Fatal("missing first stream")
	}
	select {
	case second = <-got:
	case <-ctx.Done():
		t.Fatal("missing second stream")
	}
	if first.Path != "/one" || first.ID != 1 {
		t.Fatalf("post stream %+v", first)
	}
	if second.Path != "/two" || second.ID != 3 {
		t.Fatalf("get after trailers %+v (trailer HEADERS must not steal stream 3)", second)
	}
}

func TestServeClientConcurrentStreamIDs(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := make(chan Stream, 2)
	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(2)
	go func() {
		_ = ServeClient(ctx, server, func(ctx context.Context, in Stream) (*http.Response, []model.Header, error) {
			inCopy := in
			inCopy.Body = nil
			started.Done()
			<-release
			got <- inCopy
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       http.NoBody,
			}, nil, nil
		})
	}()
	cc, err := (&http2.Transport{}).NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()

	errc := make(chan error, 2)
	for _, path := range []string{"/a", "/b"} {
		path := path
		go func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab"+path, nil)
			if err != nil {
				errc <- err
				return
			}
			resp, err := cc.RoundTrip(req)
			if err != nil {
				errc <- err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			errc <- nil
		}()
	}
	done := make(chan struct{})
	go func() {
		started.Wait()
		close(release)
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("handlers did not both start")
	}
	ids := map[string]uint32{}
	for i := 0; i < 2; i++ {
		select {
		case in := <-got:
			ids[in.Path] = in.ID
		case <-ctx.Done():
			t.Fatal("missing stream record")
		}
	}
	if ids["/a"] == 0 || ids["/b"] == 0 {
		t.Fatalf("ids %+v", ids)
	}
	if ids["/a"] == ids["/b"] {
		t.Fatalf("swapped or identical ids %+v", ids)
	}
	if (ids["/a"] != 1 && ids["/a"] != 3) || (ids["/b"] != 1 && ids["/b"] != 3) {
		t.Fatalf("want stream ids 1 and 3, got %+v", ids)
	}
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}
}

func TestServeClientUnreadDATADoesNotStall(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	paused := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = ServeClient(ctx, server, func(ctx context.Context, in Stream) (*http.Response, []model.Header, error) {
			if in.Path == "/pause" {
				close(paused)
				<-release
				_, _ = io.Copy(io.Discard, in.Body)
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("other")),
			}, nil, nil
		})
	}()
	cc, err := (&http2.Transport{}).NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()

	postErr := make(chan error, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.lab/pause", strings.NewReader("payload-bytes"))
		if err != nil {
			postErr <- err
			return
		}
		resp, err := cc.RoundTrip(req)
		if err != nil {
			postErr <- err
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		postErr <- nil
	}()
	select {
	case <-paused:
	case <-ctx.Done():
		t.Fatal("pause handler did not start")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/other", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("GET stalled behind unread POST DATA: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "other" {
		t.Fatalf("body %q", body)
	}
	close(release)
	if err := <-postErr; err != nil {
		t.Fatal(err)
	}
}

func TestServeClientLargeResponse(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	payload := strings.Repeat("x", 128*1024)
	go func() {
		_ = ServeClient(ctx, server, func(ctx context.Context, in Stream) (*http.Response, []model.Header, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(payload)),
			}, nil, nil
		})
	}()
	cc, err := (&http2.Transport{}).NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/big", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("len=%d", len(got))
	}
}

func TestServeConnPrefaceTailDoesNotReadRawConn(t *testing.T) {
	if http2.ClientPreface != prefaceHead+prefaceTailSM {
		t.Fatalf("ClientPreface %q", http2.ClientPreface)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	type acc struct {
		c   net.Conn
		err error
	}
	ac := make(chan acc, 1)
	go func() {
		c, err := ln.Accept()
		ac <- acc{c: c, err: err}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	gotAcc := <-ac
	if gotAcc.err != nil {
		t.Fatal(gotAcc.err)
	}
	server := gotAcc.c
	t.Cleanup(func() { _ = server.Close() })

	var settingsBuf bytes.Buffer
	if err := http2.NewFramer(&settingsBuf, nil).WriteSettings(); err != nil {
		t.Fatal(err)
	}
	leftover := append([]byte(prefaceTailSM), settingsBuf.Bytes()...)
	br := bufio.NewReader(io.MultiReader(bytes.NewReader(leftover), server))
	bufrw := bufio.NewReadWriter(br, bufio.NewWriter(server))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := make(chan Stream, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- ServeConn(ctx, server, bufrw, ServeOpts{Preface: PrefaceTail}, func(ctx context.Context, in Stream) (*http.Response, []model.Header, error) {
			inCopy := in
			inCopy.Body = nil
			got <- inCopy
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil, nil
		}, nil)
	}()

	fr := http2.NewFramer(client, bufio.NewReader(client))
	deadline := time.Now().Add(3 * time.Second)
	sawSettings := false
	for time.Now().Before(deadline) {
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("server SETTINGS: %v (ServeConn must not ReadFull ClientPreface from the raw conn)", err)
		}
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			if err := fr.WriteSettingsAck(); err != nil {
				t.Fatal(err)
			}
			sawSettings = true
			break
		}
	}
	if !sawSettings {
		t.Fatal("no server SETTINGS; leftover preface was probably re-read from the raw conn")
	}

	var hdr bytes.Buffer
	enc := hpack.NewEncoder(&hdr)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodGet},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "app.lab"},
		{Name: ":path", Value: "/hello"},
	} {
		if err := enc.WriteField(hf); err != nil {
			t.Fatal(err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hdr.Bytes(),
		EndHeaders:    true,
		EndStream:     true,
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case in := <-got:
		if in.Method != http.MethodGet || in.Path != "/hello" {
			t.Fatalf("stream %+v", in)
		}
	case err := <-errc:
		t.Fatalf("ServeConn: %v", err)
	case <-ctx.Done():
		t.Fatal("handler not invoked; leftover SETTINGS was eaten as a 24-byte preface")
	}
}

func TestServeConnEnableConnectProtocolSetting(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		_ = ServeConn(ctx, server, nil, ServeOpts{Preface: PrefaceFull, EnableConnectProtocol: true},
			func(context.Context, Stream) (*http.Response, []model.Header, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil, nil
			}, nil)
	}()
	if _, err := client.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(client, client)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	enable := false
	max := uint32(0)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		sf, ok := f.(*http2.SettingsFrame)
		if !ok || sf.IsAck() {
			continue
		}
		_ = sf.ForeachSetting(func(s http2.Setting) error {
			if s.ID == SettingEnableConnectProtocol && s.Val == 1 {
				enable = true
			}
			if s.ID == http2.SettingMaxConcurrentStreams {
				max = s.Val
			}
			return nil
		})
		break
	}
	if !enable {
		t.Fatal("missing ENABLE_CONNECT_PROTOCOL=1")
	}
	if max != maxConcurrentStreams {
		t.Fatalf("MAX_CONCURRENT_STREAMS=%d", max)
	}
}

func TestServeClientOmitsEnableConnectProtocol(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		_ = ServeClient(ctx, server, func(context.Context, Stream) (*http.Response, []model.Header, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil, nil
		})
	}()
	if _, err := client.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(client, client)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		sf, ok := f.(*http2.SettingsFrame)
		if !ok || sf.IsAck() {
			continue
		}
		enable := false
		_ = sf.ForeachSetting(func(s http2.Setting) error {
			if s.ID == SettingEnableConnectProtocol && s.Val == 1 {
				enable = true
			}
			return nil
		})
		if enable {
			t.Fatal("ServeClient must not advertise ENABLE_CONNECT_PROTOCOL")
		}
		return
	}
	t.Fatal("no server SETTINGS")
}

func TestServeConnSurfacesProtocolAndTunnel(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := make(chan Stream, 1)
	go func() {
		_ = ServeConn(ctx, server, nil, ServeOpts{Preface: PrefaceFull, EnableConnectProtocol: true},
			func(context.Context, Stream) (*http.Response, []model.Header, error) {
				t.Error("CONNECT must not use StreamHandler when tun is set")
				return nil, nil, ErrInnerCONNECT
			},
			func(ctx context.Context, in Stream) (Tunnel, error) {
				inCopy := in
				inCopy.Body = nil
				got <- inCopy
				return Tunnel{
					Kind: TunnelWebSocket,
					AfterAck: func(c net.Conn) {
						buf := make([]byte, 16)
						n, _ := c.Read(buf)
						if n > 0 {
							_, _ = c.Write(buf[:n])
						}
						_ = c.Close()
					},
				}, nil
			})
	}()
	if _, err := client.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(client, client)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	ackSettings(t, fr)
	var hdr bytes.Buffer
	enc := hpack.NewEncoder(&hdr)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":protocol", Value: "websocket"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "app.lab"},
		{Name: ":path", Value: "/ws"},
	} {
		if err := enc.WriteField(hf); err != nil {
			t.Fatal(err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hdr.Bytes(),
		EndHeaders:    true,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case in := <-got:
		if in.Protocol != "websocket" || in.Method != http.MethodConnect || in.Path != "/ws" {
			t.Fatalf("stream %+v", in)
		}
	case <-ctx.Done():
		t.Fatal("tunnel handler not invoked")
	}
	if !readH2Status(t, fr, 1, "200") {
		t.Fatal("want :status=200")
	}
	if err := fr.WriteData(1, false, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	gotData := readH2Data(t, fr, 1)
	if string(gotData) != "hi" {
		t.Fatalf("echo %q", gotData)
	}
}

func TestServeConnPrefaceTailRequiresLeftover(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := ServeConn(ctx, a, nil, ServeOpts{Preface: PrefaceTail}, func(context.Context, Stream) (*http.Response, []model.Header, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil, nil
	}, nil)
	if err == nil {
		t.Fatal("expected PrefaceTail without leftover to fail")
	}
}

func TestServeConnTunnelRawSplices(t *testing.T) {
	originClient, originServer := net.Pipe()
	t.Cleanup(func() {
		_ = originClient.Close()
		_ = originServer.Close()
	})
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 16)
		n, _ := originServer.Read(buf)
		got <- append([]byte(nil), buf[:n]...)
		_, _ = originServer.Write([]byte("pong"))
		_ = originServer.Close()
	}()

	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		_ = ServeConn(ctx, server, nil, ServeOpts{Preface: PrefaceFull},
			func(context.Context, Stream) (*http.Response, []model.Header, error) {
				t.Error("CONNECT must not use StreamHandler when tun is set")
				return nil, nil, ErrInnerCONNECT
			},
			func(context.Context, Stream) (Tunnel, error) {
				return Tunnel{Kind: TunnelRaw, Origin: originClient}, nil
			})
	}()
	if _, err := client.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(client, client)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	ackSettings(t, fr)
	var hdr bytes.Buffer
	enc := hpack.NewEncoder(&hdr)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":authority", Value: "app.lab:9"},
	} {
		if err := enc.WriteField(hf); err != nil {
			t.Fatal(err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hdr.Bytes(),
		EndHeaders:    true,
	}); err != nil {
		t.Fatal(err)
	}
	if !readH2Status(t, fr, 1, "200") {
		t.Fatal("want :status=200")
	}
	if err := fr.WriteData(1, false, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-got:
		if string(b) != "ping" {
			t.Fatalf("origin %q", b)
		}
	case <-ctx.Done():
		t.Fatal("origin did not see spliced DATA")
	}
	if string(readH2Data(t, fr, 1)) != "pong" {
		t.Fatal("want spliced origin DATA")
	}
}

func TestServeConnNilTunCONNECTUsesStreamHandler(t *testing.T) {
	client, server := h2TLSPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	saw := make(chan Stream, 1)
	go func() {
		_ = ServeConn(ctx, server, nil, ServeOpts{Preface: PrefaceFull},
			func(ctx context.Context, in Stream) (*http.Response, []model.Header, error) {
				inCopy := in
				inCopy.Body = nil
				saw <- inCopy
				return nil, nil, ErrInnerCONNECT
			}, nil)
	}()
	if _, err := client.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(client, client)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	ackSettings(t, fr)
	var hdr bytes.Buffer
	enc := hpack.NewEncoder(&hdr)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":authority", Value: "app.lab:443"},
	} {
		if err := enc.WriteField(hf); err != nil {
			t.Fatal(err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hdr.Bytes(),
		EndHeaders:    true,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case in := <-saw:
		if in.Method != http.MethodConnect {
			t.Fatalf("method %q", in.Method)
		}
	case <-ctx.Done():
		t.Fatal("StreamHandler not invoked")
	}
	expectRST(t, fr, 1, http2.ErrCodeProtocol)
}

func ackSettings(t *testing.T, fr *http2.Framer) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			if err := fr.WriteSettingsAck(); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("no server SETTINGS")
}

func readH2Status(t *testing.T, fr *http2.Framer, id uint32, want string) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		switch hf := f.(type) {
		case *http2.MetaHeadersFrame:
			if hf.StreamID != id {
				continue
			}
			return hf.PseudoValue("status") == want
		case *http2.RSTStreamFrame:
			if hf.StreamID == id {
				t.Fatalf("RST %v", hf.ErrCode)
			}
		}
	}
	return false
}

func readH2Data(t *testing.T, fr *http2.Framer, id uint32) []byte {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		df, ok := f.(*http2.DataFrame)
		if !ok || df.StreamID != id {
			continue
		}
		return append([]byte(nil), df.Data()...)
	}
	t.Fatal("no DATA")
	return nil
}

func expectRST(t *testing.T, fr *http2.Framer, id uint32, code http2.ErrCode) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		rst, ok := f.(*http2.RSTStreamFrame)
		if !ok || rst.StreamID != id {
			continue
		}
		if rst.ErrCode != code {
			t.Fatalf("RST %v want %v", rst.ErrCode, code)
		}
		return
	}
	t.Fatal("no RST_STREAM")
}

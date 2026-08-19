package http2x

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"golang.org/x/net/http2"
)

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

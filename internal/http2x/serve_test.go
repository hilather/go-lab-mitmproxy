package http2x

import (
	"context"
	"io"
	"net/http"
	"strings"
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

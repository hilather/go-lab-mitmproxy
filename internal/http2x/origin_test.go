package http2x

import (
	"context"
	"io"
	"net/http"
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
	if tr.DialTLSContext != nil {
		t.Fatal("DialTLSContext must stay nil")
	}
	// D28: the DialTLS field (deprecated alias) must stay unset.
	if tr.DialTLS != nil { //nolint:staticcheck
		t.Fatal("DialTLS must stay nil")
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

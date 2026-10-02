package proxy

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestInnerRSTCancelsStalledOriginH2ResponseAndUpload(t *testing.T) {
	canceled := make(chan struct{})
	origin := startTLSOriginH2(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stall" {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(canceled)
			return
		}
		_, _ = io.WriteString(w, "sibling")
	}))
	_, port := hostPort(t, origin)
	spec := interceptH2OriginSpec(t, port)
	spec.Proxy.Admission.UpstreamTimeout = time.Minute
	px := startProxy(t, Options{Spec: spec, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	reqCtx, abort := context.WithCancel(ctx)
	defer abort()
	uploadR, uploadW := io.Pipe()
	defer func() { _ = uploadW.Close() }()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, "https://app.lab/stall", uploadR)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	abort()
	_ = resp.Body.Close()
	select {
	case <-canceled:
	case <-ctx.Done():
		t.Fatal("inner RST left origin h2 response stalled")
	}
	uploadDone := make(chan error, 1)
	go func() { _, err := uploadW.Write([]byte("late")); uploadDone <- err }()
	select {
	case err := <-uploadDone:
		if err == nil {
			t.Fatal("canceled upload remains writable")
		}
	case <-ctx.Done():
		t.Fatal("request body reader remained blocked")
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "https://app.lab/sibling", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != "sibling" {
		t.Fatalf("sibling status=%d body=%q err=%v", resp.StatusCode, body, err)
	}
}

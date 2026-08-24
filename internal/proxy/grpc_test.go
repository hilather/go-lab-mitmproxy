package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/grpcx"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func grpcHelloFrame() []byte {
	return grpcx.Frame(false, []byte{0x0a, 0x02, 'h', 'i'})
}

func grpcMalformedFrame() []byte {
	return []byte{0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xff}
}

func findGRPCFlow(sink *Null, path string) *model.Flow {
	for _, f := range sink.Last() {
		if f != nil && strings.Contains(f.URL, path) {
			return f
		}
	}
	return nil
}

func TestInterceptGRPCDecodeWellFormed(t *testing.T) {
	frame := grpcHelloFrame()
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, frame) {
			t.Errorf("origin body %x", body)
		}
		w.Header().Set("Content-Type", "application/grpc")
		_, _ = w.Write(frame)
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2Spec(t, port)
	spec.Protocols.HTTP2.GRPCDecode = true
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.lab/svc/Hello", bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(got, frame) {
		t.Fatalf("status %d body %x", resp.StatusCode, got)
	}
	f := findGRPCFlow(sink, "/svc/Hello")
	if f == nil || f.GRPC == nil {
		t.Fatalf("missing grpc: %+v", sink.Last())
	}
	if f.GRPC.DecodeError != "" || len(f.GRPC.Messages) < 1 {
		t.Fatalf("grpc %+v", f.GRPC)
	}
	found := false
	for _, m := range f.GRPC.Messages {
		for _, field := range m.Fields {
			if field.Text == "hi" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("tree %+v", f.GRPC.Messages)
	}
	if px.Metrics().GRPCDecode("ok") < 1 {
		t.Fatal("expected grpc_decode ok")
	}
}

func TestInterceptGRPCDecodeFlagOff(t *testing.T) {
	frame := grpcHelloFrame()
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		_, _ = w.Write(frame)
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2Spec(t, port)
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.lab/svc/Off", bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	f := findGRPCFlow(sink, "/svc/Off")
	if f == nil {
		t.Fatalf("missing flow: %+v", sink.Last())
	}
	if f.GRPC != nil {
		t.Fatalf("flag-off must not set GRPC: %+v", f.GRPC)
	}
	if px.Metrics().GRPCDecode("ok") != 0 {
		t.Fatal("flag-off must not count decode")
	}
}

func TestInterceptGRPCMalformedFailOpen(t *testing.T) {
	frame := grpcMalformedFrame()
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, frame) {
			t.Errorf("origin body %x", body)
		}
		w.Header().Set("Content-Type", "application/grpc")
		_, _ = w.Write(frame)
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2Spec(t, port)
	spec.Protocols.HTTP2.GRPCDecode = true
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.lab/svc/Bad", bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(got, frame) {
		t.Fatalf("fail-open status %d body %x", resp.StatusCode, got)
	}
	f := findGRPCFlow(sink, "/svc/Bad")
	if f == nil || f.GRPC == nil || f.GRPC.DecodeError != model.GRPCDecodeMalformed {
		t.Fatalf("grpc %+v", f)
	}
	if px.Metrics().GRPCDecode("malformed") < 1 {
		t.Fatal("expected grpc_decode malformed")
	}
}

func TestInterceptGRPCWebOpaque(t *testing.T) {
	frame := grpcHelloFrame()
	origin := startTLSOrigin(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/grpc-web+proto" {
			t.Errorf("content-type %q", r.Header.Get("Content-Type"))
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		_, _ = w.Write(frame)
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2Spec(t, port)
	spec.Protocols.HTTP2.GRPCDecode = true
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.lab/svc/Web", bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc-web+proto")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	f := findGRPCFlow(sink, "/svc/Web")
	if f == nil {
		t.Fatalf("missing flow: %+v", sink.Last())
	}
	if f.GRPC != nil {
		t.Fatalf("grpc-web must stay opaque: %+v", f.GRPC)
	}
	ct := ""
	for _, h := range f.Request.Headers {
		if strings.EqualFold(h.Name, "content-type") {
			ct = h.Value
		}
	}
	if ct != "application/grpc-web+proto" {
		t.Fatalf("content-type not recorded: %+v", f.Request.Headers)
	}
	if px.Metrics().GRPCDecode("skipped") < 1 {
		t.Fatal("expected grpc_decode skipped")
	}
}

func TestInterceptGRPCOriginH2(t *testing.T) {
	frame := grpcHelloFrame()
	origin := startTLSOriginH2(t, originCert(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc+proto")
		_, _ = w.Write(frame)
	}))
	_, port := hostPort(t, origin)
	sink := NewNull()
	spec := interceptH2OriginSpec(t, port)
	spec.Protocols.HTTP2.GRPCDecode = true
	px := startProxy(t, Options{Spec: spec, Sink: sink, Resolver: appLabResolver()})
	cc := h2ClientConnViaProxy(t, px.Addr().String(), strconv.Itoa(port), px.Authority().CertPool())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.lab/svc/H2", bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc+proto")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(got, frame) {
		t.Fatalf("status %d body %x proto %q", resp.StatusCode, got, resp.Proto)
	}
	f := findGRPCFlow(sink, "/svc/H2")
	if f == nil || f.GRPC == nil || f.GRPC.DecodeError != "" {
		t.Fatalf("grpc %+v flow=%+v", f.GRPC, f)
	}
}

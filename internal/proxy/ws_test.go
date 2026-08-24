package proxy

import (
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
	"github.com/hilather/go-lab-mitmproxy/internal/wsx"
)

func echoWSOrigin(t *testing.T) string {
	t.Helper()
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", 500)
			return
		}
		c, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = bufrw.Flush()
		for {
			fr, err := wsx.ReadFrame(bufrw, 0)
			if err != nil {
				return
			}
			fr.Masked = false
			fr.MaskKey = [4]byte{}
			if err := wsx.WriteFrame(bufrw, fr); err != nil {
				return
			}
			_ = bufrw.Flush()
			if fr.Opcode == wsx.OpcodeClose {
				return
			}
		}
	}))
	return origin
}

func inspectSpec(t *testing.T) model.Spec {
	t.Helper()
	spec := loadSpec(t)
	spec.Protocols.WebSocket.InspectFrames = true
	return spec
}

func writeWS(t *testing.T, c *proxytest.Client, fr wsx.Frame) {
	t.Helper()
	var buf bytes.Buffer
	if err := wsx.WriteFrame(&buf, fr); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteRaw(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func readWS(t *testing.T, c *proxytest.Client) wsx.Frame {
	t.Helper()
	fr, err := wsx.ReadFrame(c.Reader(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return fr
}

func TestWebSocketFramesOffStillCopies(t *testing.T) {
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", 500)
			return
		}
		c, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = bufrw.Flush()
		buf := make([]byte, 64)
		n, _ := bufrw.Read(buf)
		_, _ = bufrw.Write(buf[:n])
		_ = bufrw.Flush()
	}))
	sink := NewNull()
	px := startProxy(t, Options{Sink: sink})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteRequest(
		"GET http://"+origin+"/ws HTTP/1.1",
		"Host: "+origin,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
	); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if err := c.WriteRaw([]byte("ping-ws")); err != nil {
		t.Fatal(err)
	}
	echo, err := c.ReadN(7)
	if err != nil {
		t.Fatal(err)
	}
	if string(echo) != "ping-ws" {
		t.Fatalf("echo %q", echo)
	}
	for _, f := range sink.Last() {
		if f.Protocol == model.FlowProtocolWebSocket && f.WebSocket != nil {
			t.Fatalf("flag-off must not capture frames: %+v", f.WebSocket)
		}
	}
}

func TestWebSocketFramesTranscript(t *testing.T) {
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", 500)
			return
		}
		c, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = bufrw.Flush()
		_, _ = io.Copy(io.Discard, bufrw)
	}))
	px := startProxy(t, Options{Spec: inspectSpec(t)})
	proxytest.PlayTranscript(t, px.Addr().String(), testdataProxy(t, "upgrade-websocket-frames.txt"), map[string]string{
		"HOST": origin,
	})
}

func TestWebSocketInspectCapturesFrames(t *testing.T) {
	origin := echoWSOrigin(t)
	sink := NewNull()
	px := startProxy(t, Options{Spec: inspectSpec(t), Sink: sink})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WriteRequest(
		"GET http://"+origin+"/ws HTTP/1.1",
		"Host: "+origin,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
	); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("hello")})
	got := readWS(t, c)
	if string(got.Payload) != "hello" || got.Opcode != wsx.OpcodeText || got.Masked {
		t.Fatalf("echo %+v", got)
	}
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_ = readWS(t, c)
	_ = c.Close()

	f := waitWSFlow(t, sink)
	if f.WebSocket == nil || f.WebSocket.FrameCount < 2 {
		t.Fatalf("ws %+v", f.WebSocket)
	}
	var sawText, sawClose bool
	for _, fr := range f.WebSocket.Frames {
		if fr.Opcode == "text" && fr.Payload != nil && string(fr.Payload) == "hello" {
			sawText = true
			if !fr.Masked && fr.Direction == model.WSDirectionClient {
				t.Fatal("client text should record masked")
			}
		}
		if fr.Opcode == "close" {
			sawClose = true
		}
	}
	if !sawText || !sawClose {
		t.Fatalf("frames %+v", f.WebSocket.Frames)
	}
	if px.Metrics().WSFrames("text") < 1 {
		t.Fatal("expected ws_frames_total text")
	}
}

func TestWebSocketInspectTruncatesPayload(t *testing.T) {
	origin := echoWSOrigin(t)
	sink := NewNull()
	spec := inspectSpec(t)
	spec.Store.MaxBodyBytes = 4
	px := startProxy(t, Options{Spec: spec, Sink: sink})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WriteRequest(
		"GET http://"+origin+"/ws HTTP/1.1",
		"Host: "+origin,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
	); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{9, 8, 7, 6}, Payload: []byte("hello-world")})
	got := readWS(t, c)
	if string(got.Payload) != "hello-world" {
		t.Fatalf("forwarded %q", got.Payload)
	}
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{9, 8, 7, 6}, CloseCode: 1000})
	_ = readWS(t, c)
	_ = c.Close()
	f := waitWSFlow(t, sink)
	if f.WebSocket == nil || !f.WebSocket.Truncated || !f.Truncated {
		t.Fatalf("want truncated, got %+v", f.WebSocket)
	}
	if len(f.WebSocket.Frames) == 0 || string(f.WebSocket.Frames[0].Payload) != "hell" {
		t.Fatalf("stored %+v", f.WebSocket.Frames)
	}
}

func TestWebSocketInspectControlTooLarge(t *testing.T) {
	origin := echoWSOrigin(t)
	sink := NewNull()
	px := startProxy(t, Options{Spec: inspectSpec(t), Sink: sink})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WriteRequest(
		"GET http://"+origin+"/ws HTTP/1.1",
		"Host: "+origin,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
	); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if err := c.WriteRaw([]byte{0x89, 126}); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, c.Reader())
	_ = c.Close()
	f := waitWSFlow(t, sink)
	if f.Error != model.WSErrorProtocol {
		t.Fatalf("error=%q flow=%+v", f.Error, f)
	}
}

func waitWSFlow(t *testing.T, sink *Null) *model.Flow {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range sink.Last() {
			if f.Protocol == model.FlowProtocolWebSocket {
				return f
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no websocket flow, last=%+v", sink.Last())
	return nil
}

func TestWebSocketInspectPingForwarded(t *testing.T) {
	var sawPing bool
	origin, _ := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		c, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = bufrw.Flush()
		fr, err := wsx.ReadFrame(bufrw, 0)
		if err != nil {
			return
		}
		if fr.Opcode == wsx.OpcodePing && string(fr.Payload) == "z" {
			sawPing = true
			_ = wsx.WriteFrame(bufrw, wsx.Frame{Fin: true, Opcode: wsx.OpcodePong, Payload: []byte("z")})
			_ = bufrw.Flush()
		}
		fr, err = wsx.ReadFrame(bufrw, 0)
		if err != nil {
			return
		}
		fr.Masked = false
		fr.MaskKey = [4]byte{}
		_ = wsx.WriteFrame(bufrw, fr)
		_ = bufrw.Flush()
	}))
	sink := NewNull()
	px := startProxy(t, Options{Spec: inspectSpec(t), Sink: sink})
	c, err := proxytest.Dial(px.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WriteRequest(
		"GET http://"+origin+"/ws HTTP/1.1",
		"Host: "+origin,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadResponse(); err != nil {
		t.Fatal(err)
	}
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodePing, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("z")})
	pong := readWS(t, c)
	if pong.Opcode != wsx.OpcodePong || string(pong.Payload) != "z" {
		t.Fatalf("pong %+v", pong)
	}
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_ = readWS(t, c)
	_ = c.Close()
	if !sawPing {
		t.Fatal("origin did not see forwarded ping")
	}
	_ = waitWSFlow(t, sink)
}

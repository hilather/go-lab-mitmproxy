package proxy

import (
	"bytes"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/compiler"
	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/proxytest"
	"github.com/hilather/go-lab-mitmproxy/internal/rules"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
	"github.com/hilather/go-lab-mitmproxy/internal/wsx"
)

type recordedWS struct {
	mu     sync.Mutex
	frames []wsx.Frame
	wire   []wsWire
}

type wsWire struct {
	header  wsx.Header
	payload []byte
}

func (r *recordedWS) add(fr wsx.Frame) {
	r.mu.Lock()
	r.frames = append(r.frames, fr)
	r.mu.Unlock()
}

func (r *recordedWS) addWire(h wsx.Header, payload []byte) {
	r.mu.Lock()
	r.wire = append(r.wire, wsWire{header: h, payload: append([]byte(nil), payload...)})
	r.mu.Unlock()
}

func (r *recordedWS) opcodes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, len(r.frames))
	for i, fr := range r.frames {
		out[i] = fr.Opcode
	}
	return out
}

func (r *recordedWS) sawOpcode(op byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, fr := range r.frames {
		if fr.Opcode == op {
			return true
		}
	}
	return false
}

func (r *recordedWS) saw(op byte, payload string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, fr := range r.frames {
		if fr.Opcode == op && string(fr.Payload) == payload {
			return true
		}
	}
	return false
}

func recordingWSOrigin(t *testing.T, rec *recordedWS, echo bool) string {
	t.Helper()
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
		for {
			fr, err := wsx.ReadFrame(bufrw, 0)
			if err != nil {
				return
			}
			rec.add(fr)
			if echo {
				fr.Masked = false
				fr.MaskKey = [4]byte{}
				if err := wsx.WriteFrame(bufrw, fr); err != nil {
					return
				}
				_ = bufrw.Flush()
			}
			if fr.Opcode == wsx.OpcodeClose {
				return
			}
		}
	}))
	return origin
}

func wireRecordingWSOrigin(t *testing.T, rec *recordedWS) string {
	t.Helper()
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
		for {
			h, err := wsx.ReadHeader(bufrw)
			if err != nil {
				return
			}
			payload := make([]byte, int(h.Length))
			if h.Length > 0 {
				if _, err := io.ReadFull(bufrw, payload); err != nil {
					return
				}
			}
			rec.addWire(h, payload)
			if h.Opcode == wsx.OpcodeClose {
				return
			}
		}
	}))
	return origin
}

func inspectRulesSpec(t *testing.T, items ...model.RuleSpec) model.Spec {
	t.Helper()
	spec := inspectSpec(t)
	spec.Rules = model.RulesSpec{Enabled: true, Items: items}
	return spec
}

func wsItem(id, opcode, action string) model.RuleSpec {
	return model.RuleSpec{
		ID: id, Enabled: true, Phase: model.RulePhaseWebSocket,
		Match:  model.RuleMatchSpec{Opcode: opcode},
		Action: model.RuleActionSpec{Type: action},
	}
}

func upgradeWS(t *testing.T, pxAddr, origin, path string, extra ...string) *proxytest.Client {
	t.Helper()
	c, err := proxytest.Dial(pxAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	lines := []string{
		"GET http://" + origin + path + " HTTP/1.1",
		"Host: " + origin,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
	}
	lines = append(lines, extra...)
	if err := c.WriteRequest(lines...); err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	return c
}

func TestWebSocketFrameDropOmitsTextKeepsPing(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	sink := NewNull()
	px := startProxy(t, Options{Spec: inspectRulesSpec(t, wsItem("drop-text", model.RuleOpcodeText, model.ActionDrop)), Sink: sink})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("hello")})
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodePing, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("z")})
	pong := readWS(t, c)
	if pong.Opcode != wsx.OpcodePing || string(pong.Payload) != "z" {
		t.Fatalf("echo ping %+v", pong)
	}
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_ = readWS(t, c)
	_ = c.Close()
	f := waitWSFlow(t, sink)
	if rec.saw(wsx.OpcodeText, "hello") {
		t.Fatal("origin must not see dropped text")
	}
	if !rec.saw(wsx.OpcodePing, "z") {
		t.Fatal("later ping must still be forwarded")
	}
	if px.Metrics().WSFrames("text") != 0 {
		t.Fatal("dropped text must not increment ws_frames_total")
	}
	if px.Metrics().RuleHits(model.ActionDrop) < 1 {
		t.Fatal("expected drop hit")
	}
	var dropped model.WebSocketFrame
	for _, fr := range f.WebSocket.Frames {
		if fr.Opcode == "text" && fr.Action == model.ActionDrop {
			dropped = fr
		}
	}
	if string(dropped.Payload) != "hello" {
		t.Fatalf("captured drop %+v", dropped)
	}
	if len(f.RuleIDs) == 0 || f.RuleIDs[0] != "drop-text" {
		t.Fatalf("ruleIds %+v", f.RuleIDs)
	}
}

func TestWebSocketFrameBlockClosesBoth(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	sink := NewNull()
	px := startProxy(t, Options{Spec: inspectRulesSpec(t, wsItem("kill-bin", model.RuleOpcodeBinary, model.ActionBlock)), Sink: sink})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeBinary, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("xx")})
	_, _ = io.Copy(io.Discard, c.Reader())
	_ = c.Close()
	f := waitWSFlow(t, sink)
	if rec.saw(wsx.OpcodeBinary, "xx") {
		t.Fatal("origin must not see blocked binary")
	}
	if rec.saw(wsx.OpcodePing, "later") {
		t.Fatal("later frames must not be delivered")
	}
	if f.Error != "" {
		t.Fatalf("block must not set Error: %q", f.Error)
	}
	if f.State != model.FlowStateCompleted {
		t.Fatalf("state %q", f.State)
	}
	if px.Metrics().RuleHits(model.ActionBlock) < 1 {
		t.Fatal("expected block hit")
	}
	if px.Metrics().WSFrames("binary") != 0 {
		t.Fatal("blocked frame must not increment ws_frames_total")
	}
}

func TestWebSocketFrameRulesInspectOffCopy(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	spec := loadSpec(t)
	spec.Rules = model.RulesSpec{Enabled: true, Items: []model.RuleSpec{wsItem("drop-text", model.RuleOpcodeText, model.ActionDrop)}}
	sink := NewNull()
	px := startProxy(t, Options{Spec: spec, Sink: sink})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("hello")})
	got := readWS(t, c)
	if string(got.Payload) != "hello" {
		t.Fatalf("copy %q", got.Payload)
	}
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_ = readWS(t, c)
	_ = c.Close()
	if !rec.saw(wsx.OpcodeText, "hello") {
		t.Fatal("inspect off must forward the frame")
	}
	if px.Metrics().RuleHits(model.ActionDrop) != 0 {
		t.Fatal("copy path must not count drop")
	}
}

func TestWebSocketResponseRulesStillLateSkipWithFrameRules(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	spec := inspectRulesSpec(t,
		model.RuleSpec{ID: "resp-drop", Enabled: true, Phase: model.RulePhaseResponse, Action: model.RuleActionSpec{Type: model.ActionDrop}},
		model.RuleSpec{ID: "resp-delay", Enabled: true, Phase: model.RulePhaseResponse, Action: model.RuleActionSpec{Type: model.ActionDelay, Delay: time.Millisecond}},
		wsItem("drop-text", model.RuleOpcodeText, model.ActionDrop),
	)
	sink := NewNull()
	px := startProxy(t, Options{Spec: spec, Sink: sink})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodePing, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("z")})
	_ = readWS(t, c)
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_ = readWS(t, c)
	_ = c.Close()
	if px.Metrics().RuleHits(rules.ActionLateSkip) < 1 {
		t.Fatal("101 must still late_skip response-phase items")
	}
	if !rec.saw(wsx.OpcodePing, "z") {
		t.Fatal("response-phase drop must not omit frames")
	}
}

func TestWebSocketMatchProtocolToken(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	spec := inspectRulesSpec(t, model.RuleSpec{
		ID: "ws-only", Enabled: true, Phase: model.RulePhaseWebSocket,
		Match:  model.RuleMatchSpec{Protocol: model.FlowProtocolWebSocket, Opcode: model.RuleOpcodeText},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	})
	px := startProxy(t, Options{Spec: spec, Sink: NewNull()})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("hello")})
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_, _ = io.Copy(io.Discard, c.Reader())
	_ = c.Close()
	if rec.saw(wsx.OpcodeText, "hello") {
		t.Fatal("match.protocol websocket must drop HTTP/1.1 inspect text")
	}

	rec2 := &recordedWS{}
	origin2 := recordingWSOrigin(t, rec2, true)
	spec2 := inspectRulesSpec(t, model.RuleSpec{
		ID: "h1", Enabled: true, Phase: model.RulePhaseWebSocket,
		Match:  model.RuleMatchSpec{Protocol: model.FlowProtocolHTTP11, Opcode: model.RuleOpcodeText},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	})
	px2 := startProxy(t, Options{Spec: spec2, Sink: NewNull()})
	c2 := upgradeWS(t, px2.Addr().String(), origin2, "/ws")
	writeWS(t, c2, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("hello")})
	got := readWS(t, c2)
	if string(got.Payload) != "hello" {
		t.Fatalf("http/1.1 protocol token must miss: %q", got.Payload)
	}
}

func TestWebSocketDroppedCloseContinues(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	px := startProxy(t, Options{Spec: inspectRulesSpec(t, wsItem("drop-close", model.RuleOpcodeClose, model.ActionDrop)), Sink: NewNull()})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodePing, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("z")})
	_ = readWS(t, c)
	_ = c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !rec.saw(wsx.OpcodePing, "z") {
		time.Sleep(10 * time.Millisecond)
	}
	if rec.sawOpcode(wsx.OpcodeClose) {
		t.Fatal("dropped close must not reach origin")
	}
	if !rec.saw(wsx.OpcodePing, "z") {
		t.Fatal("later ping must still be evaluated after dropped close")
	}
}

func TestWebSocketForwardedCloseEndsPump(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	px := startProxy(t, Options{Spec: inspectRulesSpec(t, wsItem("drop-text", model.RuleOpcodeText, model.ActionDrop)), Sink: NewNull()})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_ = readWS(t, c)
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodePing, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("late")})
	time.Sleep(50 * time.Millisecond)
	if rec.saw(wsx.OpcodePing, "late") {
		t.Fatal("forwarded close must end that pump")
	}
}

func TestWebSocketPayloadContainsUnmasked(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	spec := inspectRulesSpec(t, model.RuleSpec{
		ID: "secret", Enabled: true, Phase: model.RulePhaseWebSocket,
		Match:  model.RuleMatchSpec{Opcode: model.RuleOpcodeText, PayloadContains: "secret"},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	})
	px := startProxy(t, Options{Spec: spec, Sink: NewNull()})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{9, 8, 7, 6}, Payload: []byte("the secret")})
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{9, 8, 7, 6}, CloseCode: 1000})
	_, _ = io.Copy(io.Discard, c.Reader())
	_ = c.Close()
	if rec.saw(wsx.OpcodeText, "the secret") {
		t.Fatal("unmasked payloadContains must drop masked client text")
	}
}

func TestWebSocketContinuationIsFragmentOnly(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	spec := inspectRulesSpec(t, model.RuleSpec{
		ID: "cont", Enabled: true, Phase: model.RulePhaseWebSocket,
		Match:  model.RuleMatchSpec{Opcode: model.RuleOpcodeContinuation, PayloadContains: "secret"},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	})
	px := startProxy(t, Options{Spec: spec, Sink: NewNull()})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	writeWS(t, c, wsx.Frame{Fin: false, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("se")})
	_ = readWS(t, c)
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeContinuation, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("secret")})
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_, _ = io.Copy(io.Discard, c.Reader())
	_ = c.Close()
	if rec.saw(wsx.OpcodeContinuation, "secret") {
		t.Fatal("continuation payloadContains must match the fragment only and drop it")
	}
	if !rec.saw(wsx.OpcodeText, "se") {
		t.Fatal("text fragment without secret must still forward")
	}
}

func TestWebSocketOversizedPayloadContainsThenOpcodeDrop(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	spec := inspectRulesSpec(t,
		model.RuleSpec{ID: "secret", Enabled: true, Phase: model.RulePhaseWebSocket, Match: model.RuleMatchSpec{PayloadContains: "secret"}, Action: model.RuleActionSpec{Type: model.ActionDrop}},
		wsItem("drop-bin", model.RuleOpcodeBinary, model.ActionDrop),
	)
	spec.Store.MaxBodyBytes = 4
	sink := NewNull()
	px := startProxy(t, Options{Spec: spec, Sink: sink})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	payload := bytes.Repeat([]byte("n"), 64)
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeBinary, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: payload})
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_, _ = io.Copy(io.Discard, c.Reader())
	_ = c.Close()
	f := waitWSFlow(t, sink)
	if rec.saw(wsx.OpcodeBinary, string(payload)) {
		t.Fatal("later opcode-only drop must omit the oversized frame")
	}
	if f.Error == model.WSErrorProtocol {
		t.Fatal("oversized miss must not be Error=websocket")
	}
	if f.WebSocket == nil || len(f.WebSocket.Frames) == 0 || f.WebSocket.Frames[0].Action != model.ActionDrop {
		t.Fatalf("want captured drop prefix, got %+v", f.WebSocket)
	}
}

func TestWebSocketCloseLength1BeforeMatch(t *testing.T) {
	sink := NewNull()
	px := startProxy(t, Options{Spec: inspectRulesSpec(t, model.RuleSpec{
		ID: "any", Enabled: true, Phase: model.RulePhaseWebSocket, Action: model.RuleActionSpec{Type: model.ActionDrop},
	}), Sink: sink})
	c := upgradeWS(t, px.Addr().String(), echoWSOrigin(t), "/ws")
	if err := c.WriteRaw([]byte{0x88, 0x81, 1, 2, 3, 4, 0}); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, c.Reader())
	_ = c.Close()
	f := waitWSFlow(t, sink)
	if f.Error != model.WSErrorProtocol {
		t.Fatalf("close length 1 must Error=websocket, got %q", f.Error)
	}
	if px.Metrics().RuleHits(model.ActionDrop) != 0 {
		t.Fatal("empty-match drop must not swallow close-length-1")
	}
}

func TestWebSocketControlTooLargeWithRules(t *testing.T) {
	sink := NewNull()
	px := startProxy(t, Options{Spec: inspectRulesSpec(t, wsItem("drop-text", model.RuleOpcodeText, model.ActionDrop)), Sink: sink})
	c := upgradeWS(t, px.Addr().String(), echoWSOrigin(t), "/ws")
	if err := c.WriteRaw([]byte{0x89, 126}); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, c.Reader())
	_ = c.Close()
	f := waitWSFlow(t, sink)
	if f.Error != model.WSErrorProtocol {
		t.Fatalf("control >125 must Error=websocket, got %q", f.Error)
	}
}

func TestWebSocketSnapshotPathAndHeader(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	spec := inspectRulesSpec(t, model.RuleSpec{
		ID: "snap", Enabled: true, Phase: model.RulePhaseWebSocket,
		Match:  model.RuleMatchSpec{PathPrefix: "/ws", HeaderName: "X-Lab"},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	})
	px := startProxy(t, Options{Spec: spec, Sink: NewNull()})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws", "X-Lab: 1")
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("hello")})
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_, _ = io.Copy(io.Discard, c.Reader())
	_ = c.Close()
	if rec.saw(wsx.OpcodeText, "hello") {
		t.Fatal("pathPrefix /ws + headerName must drop using the upgrade snapshot")
	}
}

func TestWebSocketPayloadContainsUsesFullCapNotRemain(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	spec := inspectRulesSpec(t, model.RuleSpec{
		ID: "secret", Enabled: true, Phase: model.RulePhaseWebSocket,
		Match:  model.RuleMatchSpec{PayloadContains: "secret"},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	})
	spec.Store.MaxBodyBytes = 16
	px := startProxy(t, Options{Spec: spec, Sink: NewNull()})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeBinary, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: bytes.Repeat([]byte("a"), 12)})
	_ = readWS(t, c)
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("secret!!")})
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_, _ = io.Copy(io.Discard, c.Reader())
	_ = c.Close()
	if rec.saw(wsx.OpcodeText, "secret!!") {
		t.Fatal("second-frame payloadContains must use full maxBodyBytes, not storeRemain")
	}
}

func TestWebSocketPayloadContainsMissKeepsMask(t *testing.T) {
	rec := &recordedWS{}
	origin := wireRecordingWSOrigin(t, rec)
	spec := inspectRulesSpec(t, model.RuleSpec{
		ID: "secret", Enabled: true, Phase: model.RulePhaseWebSocket,
		Match:  model.RuleMatchSpec{PayloadContains: "nope"},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	})
	px := startProxy(t, Options{Spec: spec, Sink: NewNull()})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	key := [4]byte{1, 2, 3, 4}
	payload := []byte("hello")
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: key, Payload: payload})
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: key, CloseCode: 1000})
	_ = c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec.mu.Lock()
		n := len(rec.wire)
		rec.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.wire) == 0 {
		t.Fatal("origin saw no frames")
	}
	got := rec.wire[0]
	if !got.header.Masked || got.header.MaskKey != key {
		t.Fatalf("mask %+v key %v", got.header, got.header.MaskKey)
	}
	want := append([]byte(nil), payload...)
	for i := range want {
		want[i] ^= key[i&3]
	}
	if !bytes.Equal(got.payload, want) {
		t.Fatalf("wire payload %x want %x", got.payload, want)
	}
}

func TestWebSocketOversizedMissNoWinnerStreams(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	spec := inspectRulesSpec(t, model.RuleSpec{
		ID: "secret", Enabled: true, Phase: model.RulePhaseWebSocket,
		Match:  model.RuleMatchSpec{PayloadContains: "secret"},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	})
	spec.Store.MaxBodyBytes = 4
	sink := NewNull()
	px := startProxy(t, Options{Spec: spec, Sink: sink})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	payload := bytes.Repeat([]byte("n"), 64)
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeBinary, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: payload})
	got := readWS(t, c)
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("streamed %d want %d", len(got.Payload), len(payload))
	}
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_ = readWS(t, c)
	_ = c.Close()
	f := waitWSFlow(t, sink)
	if f.Error == model.WSErrorProtocol {
		t.Fatal("oversized miss with no later winner must not be Error=websocket")
	}
}

func TestWebSocketEarlierPathMissStillContentMatches(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	spec := inspectRulesSpec(t,
		model.RuleSpec{
			ID: "admin", Enabled: true, Phase: model.RulePhaseWebSocket,
			Match:  model.RuleMatchSpec{Opcode: model.RuleOpcodeText, PathPrefix: "/admin"},
			Action: model.RuleActionSpec{Type: model.ActionDrop},
		},
		model.RuleSpec{
			ID: "secret", Enabled: true, Phase: model.RulePhaseWebSocket,
			Match:  model.RuleMatchSpec{PathPrefix: "/ws", PayloadContains: "secret"},
			Action: model.RuleActionSpec{Type: model.ActionDrop},
		},
	)
	px := startProxy(t, Options{Spec: spec, Sink: NewNull()})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("secret")})
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_, _ = io.Copy(io.Discard, c.Reader())
	_ = c.Close()
	if rec.saw(wsx.OpcodeText, "secret") {
		t.Fatal("later payloadContains on /ws must still content-match")
	}
}

func TestWebSocketOpenSocketKeepsPinnedEngine(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	st, err := config.Load([]byte("apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	st.Spec.Protocols.WebSocket.InspectFrames = true
	snap, err := compiler.Compile(t.Context(), st, compiler.CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	snaps := snapshot.NewStore()
	snaps.InstallBootstrap(snap)
	px := startProxy(t, Options{Spec: snap.Canonical.Spec, Snapshots: snaps, Authority: snap.CA, Sink: NewNull()})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	swapRules(t, snaps, snap, 1, true, wsItem("drop-text", model.RuleOpcodeText, model.ActionDrop))
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("old")})
	got := readWS(t, c)
	if string(got.Payload) != "old" {
		t.Fatalf("open socket must keep old engine: %q", got.Payload)
	}
	c2 := upgradeWS(t, px.Addr().String(), origin, "/ws")
	writeWS(t, c2, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("new")})
	writeWS(t, c2, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_, _ = io.Copy(io.Discard, c2.Reader())
	if rec.saw(wsx.OpcodeText, "new") {
		t.Fatal("next cleartext Upgrade must see the new drop")
	}
	if !rec.saw(wsx.OpcodeText, "old") {
		t.Fatal("in-flight inspect must forward under the old engine")
	}
}

func TestWebSocketSetFeatureEnabledFalseKeepsOpenSocket(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	st, err := config.Load([]byte("apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	st.Spec.Protocols.WebSocket.InspectFrames = true
	st.Spec.Rules = model.RulesSpec{Enabled: true, Items: []model.RuleSpec{wsItem("drop-text", model.RuleOpcodeText, model.ActionDrop)}}
	snap, err := compiler.Compile(t.Context(), st, compiler.CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	snaps := snapshot.NewStore()
	snaps.InstallBootstrap(snap)
	px := startProxy(t, Options{Spec: snap.Canonical.Spec, Snapshots: snaps, Authority: snap.CA, Sink: NewNull()})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	next := cloneCompiledState(t, snap)
	next.Spec.Rules.Enabled = false
	swapped, err := compiler.Compile(t.Context(), next, compiler.CompileOpts{Previous: snap, Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	snaps.Swap(swapped)
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("still")})
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_, _ = io.Copy(io.Discard, c.Reader())
	_ = c.Close()
	if rec.saw(wsx.OpcodeText, "still") {
		t.Fatal("open inspect socket must still match after setFeature rules.enabled=false")
	}
}

func TestWebSocketReplaceStoreCapsDoesNotChangeVisibility(t *testing.T) {
	rec := &recordedWS{}
	origin := recordingWSOrigin(t, rec, true)
	st, err := config.Load([]byte("apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	st.Spec.Protocols.WebSocket.InspectFrames = true
	st.Spec.Store.MaxBodyBytes = 1024
	st.Spec.Rules = model.RulesSpec{Enabled: true, Items: []model.RuleSpec{{
		ID: "secret", Enabled: true, Phase: model.RulePhaseWebSocket,
		Match:  model.RuleMatchSpec{PayloadContains: "secret"},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	}}}
	snap, err := compiler.Compile(t.Context(), st, compiler.CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	snaps := snapshot.NewStore()
	snaps.InstallBootstrap(snap)
	px := startProxy(t, Options{Spec: snap.Canonical.Spec, Snapshots: snaps, Authority: snap.CA, Sink: NewNull()})
	c := upgradeWS(t, px.Addr().String(), origin, "/ws")
	next := cloneCompiledState(t, snap)
	next.Spec.Store.MaxBodyBytes = 4
	swapped, err := compiler.Compile(t.Context(), next, compiler.CompileOpts{Previous: snap, Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	snaps.Swap(swapped)
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("secret")})
	writeWS(t, c, wsx.Frame{Fin: true, Opcode: wsx.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, CloseCode: 1000})
	_, _ = io.Copy(io.Discard, c.Reader())
	_ = c.Close()
	if rec.saw(wsx.OpcodeText, "secret") {
		t.Fatal("replaceStoreCaps must not change a pinned payloadContains visibility cap")
	}
}

func swapRules(t *testing.T, snaps *snapshot.Store, prev *snapshot.Snapshot, gen model.Generation, enabled bool, items ...model.RuleSpec) {
	t.Helper()
	next := cloneCompiledState(t, prev)
	next.Spec.Rules = model.RulesSpec{Enabled: enabled, Items: items}
	swapped, err := compiler.Compile(t.Context(), next, compiler.CompileOpts{Previous: prev, Generation: gen})
	if err != nil {
		t.Fatal(err)
	}
	snaps.Swap(swapped)
}

func cloneCompiledState(t *testing.T, snap *snapshot.Snapshot) *model.State {
	t.Helper()
	raw, err := config.CanonicalJSON(snap.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	st, err := config.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

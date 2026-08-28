package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/rules"
	"github.com/hilather/go-lab-mitmproxy/internal/wsx"
)

func takeBuffered(r *bufio.Reader) []byte {
	if r == nil || r.Buffered() == 0 {
		return nil
	}
	n := r.Buffered()
	b, err := r.Peek(n)
	if err != nil {
		return nil
	}
	out := append([]byte(nil), b...)
	_, _ = r.Discard(n)
	return out
}

func (s *Server) inspectUpgrade(client net.Conn, leftover []byte, upstream net.Conn, fromUp io.Reader, host string, req *http.Request, sess *ruleSession, f *model.Flow) {
	ad := s.specOf(sess).Proxy.Admission
	max := int(s.maxBodyOf(sess))
	if fromUp == nil {
		fromUp = upstream
	}
	var clientR io.Reader = client
	if len(leftover) > 0 {
		clientR = io.MultiReader(bytes.NewReader(leftover), client)
	}
	if f.WebSocket == nil {
		f.WebSocket = &model.WebSocketInfo{}
	}
	s.setSessionDeadline(ad, client, upstream)
	st := &wsInspect{
		s:        s,
		f:        f,
		max:      max,
		ad:       ad,
		client:   client,
		upstream: upstream,
		sess:     sess,
		snap: rules.Request{
			Host:    host,
			Path:    requestPath(req),
			Method:  requestMethod(req),
			Headers: requestCaptureHeaders(req),
		},
	}
	done := make(chan struct{}, 2)
	go func() {
		st.pump(clientR, upstream, client, model.WSDirectionClient)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		st.pump(fromUp, client, upstream, model.WSDirectionOrigin)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
	f.CompletedAt = time.Now().UTC()
	if f.WebSocket.Truncated {
		f.Truncated = true
	}
}

type wsInspect struct {
	s        *Server
	f        *model.Flow
	max      int
	ad       model.AdmissionSpec
	client   net.Conn
	upstream net.Conn
	sess     *ruleSession
	snap     rules.Request

	mu      sync.Mutex
	stored  int
	stopCap bool
}

func (st *wsInspect) rulesPath() bool {
	if st.sess == nil || st.sess.eng == nil {
		return false
	}
	return st.sess.eng.HasEnabledWebSocket()
}

func (st *wsInspect) pump(src io.Reader, dst io.Writer, srcConn net.Conn, dir string) {
	sessionEnd := time.Time{}
	if st.ad.SessionTimeout > 0 {
		sessionEnd = time.Now().Add(st.ad.SessionTimeout)
	}
	idle := st.ad.IdleTimeout
	if idle <= 0 {
		idle = defaultIdleTimeout
	}
	for {
		st.mu.Lock()
		fail := st.f.Error == model.WSErrorProtocol
		st.mu.Unlock()
		if fail {
			return
		}
		dl := time.Now().Add(idle)
		if !sessionEnd.IsZero() && dl.After(sessionEnd) {
			dl = sessionEnd
		}
		if srcConn != nil {
			_ = srcConn.SetReadDeadline(dl)
		}
		if rc, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = rc.SetReadDeadline(dl)
		}
		h, err := wsx.ReadHeader(src)
		if err != nil {
			if errors.Is(err, wsx.ErrProtocol) {
				st.protocolError()
			}
			return
		}
		if wc, ok := dst.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = wc.SetWriteDeadline(dl)
		}
		if !st.rulesPath() {
			if !st.pumpFast(src, dst, h, dir) {
				return
			}
			continue
		}
		if !st.pumpRules(src, dst, h, dir) {
			return
		}
	}
}

func (st *wsInspect) pumpFast(src io.Reader, dst io.Writer, h wsx.Header, dir string) bool {
	if err := wsx.WriteHeader(dst, h); err != nil {
		if errors.Is(err, wsx.ErrProtocol) {
			st.protocolError()
		}
		return false
	}
	stored, err := wsx.TeePayload(dst, src, h.Length, h.Masked, h.MaskKey, st.storeRemain())
	if err != nil {
		return false
	}
	fr := frameFromHeader(h, stored)
	if h.Opcode == wsx.OpcodeClose && h.Length == 1 {
		st.protocolError()
		return false
	}
	fillCloseCode(&fr, h, stored)
	st.captureFrame(dir, fr, h.Length)
	return fr.Opcode != wsx.OpcodeClose
}

func (st *wsInspect) pumpRules(src io.Reader, dst io.Writer, h wsx.Header, dir string) bool {
	if h.Opcode == wsx.OpcodeClose && h.Length == 1 {
		st.protocolError()
		return false
	}

	srcConsumed := false
	var wire, unmasked []byte
	in := st.snap
	in.Protocol = model.FlowProtocolWebSocket
	in.Opcode = wsx.OpcodeName(h.Opcode)
	in.Direction = dir

	if h.Length > 0 && st.sess.eng.NeedsFramePayload(in, h.Length, st.max) {
		if h.Length <= uint64(st.max) {
			wire = make([]byte, int(h.Length))
			if _, err := io.ReadFull(src, wire); err != nil {
				return false
			}
			srcConsumed = true
			unmasked = unmaskCopy(wire, h.Masked, h.MaskKey)
			in.Payload = unmasked
		}
	}

	hit := st.sess.eng.Match(model.RulePhaseWebSocket, in)
	if hit != nil && hit.Action.Type == model.ActionDrop {
		return st.applyOmit(src, h, dir, srcConsumed, unmasked, hit, model.ActionDrop)
	}
	if hit != nil && hit.Action.Type == model.ActionBlock {
		st.applyOmit(src, h, dir, srcConsumed, unmasked, hit, model.ActionBlock)
		st.closeBoth()
		return false
	}
	return st.forwardMiss(src, dst, h, dir, srcConsumed, wire, unmasked)
}

func (st *wsInspect) applyOmit(src io.Reader, h wsx.Header, dir string, srcConsumed bool, unmasked []byte, hit *rules.Hit, action string) bool {
	stored := unmasked
	if !srcConsumed {
		var err error
		stored, err = wsx.TeePayload(io.Discard, src, h.Length, h.Masked, h.MaskKey, st.storeRemain())
		if err != nil {
			return false
		}
	}
	fr := frameFromHeader(h, stored)
	fillCloseCode(&fr, h, stored)
	st.stampRule(hit, action)
	st.captureRuledFrame(dir, fr, h.Length, action)
	if st.s != nil {
		st.s.metrics.ruleHit(action)
	}
	return true
}

func (st *wsInspect) forwardMiss(src io.Reader, dst io.Writer, h wsx.Header, dir string, srcConsumed bool, wire, unmasked []byte) bool {
	if err := wsx.WriteHeader(dst, h); err != nil {
		if errors.Is(err, wsx.ErrProtocol) {
			st.protocolError()
		}
		return false
	}
	var stored []byte
	if !srcConsumed {
		var err error
		stored, err = wsx.TeePayload(dst, src, h.Length, h.Masked, h.MaskKey, st.storeRemain())
		if err != nil {
			return false
		}
	} else {
		if len(wire) > 0 {
			if _, err := dst.Write(wire); err != nil {
				return false
			}
		}
		stored = unmasked
	}
	fr := frameFromHeader(h, stored)
	fillCloseCode(&fr, h, stored)
	st.captureFrame(dir, fr, h.Length)
	return fr.Opcode != wsx.OpcodeClose
}

func (st *wsInspect) protocolError() {
	st.mu.Lock()
	st.f.Error = model.WSErrorProtocol
	st.f.State = model.FlowStateError
	st.mu.Unlock()
	st.closeBoth()
}

func (st *wsInspect) closeBoth() {
	if st.client != nil {
		_ = st.client.Close()
	}
	if st.upstream != nil {
		_ = st.upstream.Close()
	}
}

func (st *wsInspect) stampRule(hit *rules.Hit, action string) {
	st.mu.Lock()
	if hit != nil && hit.ID != "" {
		st.f.RuleIDs = append(st.f.RuleIDs, hit.ID)
	}
	if action == model.ActionBlock {
		st.f.State = model.FlowStateCompleted
	}
	st.mu.Unlock()
}

func (st *wsInspect) storeRemain() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.stopCap {
		return 0
	}
	if st.max <= 0 {
		return 1 << 20
	}
	remain := st.max - st.stored
	if remain < 0 {
		return 0
	}
	return remain
}

func (st *wsInspect) captureFrame(dir string, fr wsx.Frame, declared uint64) {
	name := wsx.OpcodeName(fr.Opcode)
	st.s.metrics.wsFrame(name)
	st.appendCapturedFrame(dir, name, fr, declared, "")
}

func (st *wsInspect) captureRuledFrame(dir string, fr wsx.Frame, declared uint64, action string) {
	st.appendCapturedFrame(dir, wsx.OpcodeName(fr.Opcode), fr, declared, action)
}

func (st *wsInspect) appendCapturedFrame(dir, name string, fr wsx.Frame, declared uint64, action string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	ws := st.f.WebSocket
	ws.FrameCount++
	if st.stopCap || len(ws.Frames) >= model.WSMaxFrames {
		ws.Truncated = true
		st.stopCap = true
		return
	}
	stored := fr.Payload
	trunc := declared > uint64(len(stored))
	if st.max > 0 {
		remain := st.max - st.stored
		if remain <= 0 {
			ws.Truncated = true
			st.stopCap = true
			return
		}
		if len(stored) > remain {
			stored = append([]byte(nil), stored[:remain]...)
			trunc = true
			ws.Truncated = true
			st.stopCap = true
		} else {
			stored = append([]byte(nil), stored...)
		}
	} else {
		stored = append([]byte(nil), stored...)
	}
	if trunc {
		ws.Truncated = true
		st.stopCap = true
	}
	st.stored += len(stored)
	ws.Frames = append(ws.Frames, model.WebSocketFrame{
		Direction: dir,
		Opcode:    name,
		OpcodeNum: int(fr.Opcode),
		Fin:       fr.Fin,
		Masked:    fr.Masked,
		CloseCode: fr.CloseCode,
		Payload:   stored,
		Size:      len(stored),
		Truncated: trunc,
		Action:    action,
	})
}

func frameFromHeader(h wsx.Header, payload []byte) wsx.Frame {
	return wsx.Frame{
		Fin:     h.Fin,
		RSV1:    h.RSV1,
		RSV2:    h.RSV2,
		RSV3:    h.RSV3,
		Opcode:  h.Opcode,
		Masked:  h.Masked,
		MaskKey: h.MaskKey,
		Payload: payload,
	}
}

func fillCloseCode(fr *wsx.Frame, h wsx.Header, stored []byte) {
	if h.Opcode == wsx.OpcodeClose && len(stored) >= 2 {
		fr.CloseCode = int(stored[0])<<8 | int(stored[1])
	}
}

func unmaskCopy(wire []byte, masked bool, key [4]byte) []byte {
	out := append([]byte(nil), wire...)
	if masked {
		for i := range out {
			out[i] ^= key[i&3]
		}
	}
	return out
}

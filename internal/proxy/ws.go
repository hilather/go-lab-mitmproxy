package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
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

func (s *Server) inspectUpgrade(client net.Conn, leftover []byte, upstream net.Conn, fromUp io.Reader, sess *ruleSession, f *model.Flow) {
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

	mu      sync.Mutex
	stored  int
	stopCap bool
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
		fr, err := wsx.ReadFrame(src, 0)
		if err != nil {
			if errors.Is(err, wsx.ErrProtocol) || errors.Is(err, wsx.ErrTooLarge) {
				st.protocolError()
			}
			return
		}
		if wc, ok := dst.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = wc.SetWriteDeadline(dl)
		}
		if err := wsx.WriteFrame(dst, fr); err != nil {
			return
		}
		st.captureFrame(dir, fr)
		if fr.Opcode == wsx.OpcodeClose {
			return
		}
	}
}

func (st *wsInspect) protocolError() {
	st.mu.Lock()
	st.f.Error = model.WSErrorProtocol
	st.f.State = model.FlowStateError
	st.mu.Unlock()
	if st.client != nil {
		_ = st.client.Close()
	}
	if st.upstream != nil {
		_ = st.upstream.Close()
	}
}

func (st *wsInspect) captureFrame(dir string, fr wsx.Frame) {
	name := wsx.OpcodeName(fr.Opcode)
	st.s.metrics.wsFrame(name)
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
	trunc := false
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
	})
}

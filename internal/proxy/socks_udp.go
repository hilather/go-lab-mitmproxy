package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

const (
	socksUDPMaxPayload   = 64 << 10
	socksUDPMaxDatagrams = 4096
	socksUDPReadBuf      = 65535
)

func (s *Server) socksAcceptUDPAssociate() bool {
	return withSpecDefaults(s.liveSpec()).Listeners.Proxy.AcceptUDPAssociate
}

func (s *Server) listenUDP(controlIP net.IP) (net.PacketConn, error) {
	if s != nil && s.listenUDPFn != nil {
		return s.listenUDPFn(controlIP)
	}
	return listenEphemeralUDP(controlIP)
}

func (s *Server) trackUDP(pc net.PacketConn) {
	if s == nil || pc == nil || pc.LocalAddr() == nil {
		return
	}
	s.mu.Lock()
	if s.udps == nil {
		s.udps = make(map[string]net.PacketConn)
	}
	s.udps[pc.LocalAddr().String()] = pc
	s.mu.Unlock()
}

func (s *Server) untrackUDP(pc net.PacketConn) {
	if s == nil || pc == nil || pc.LocalAddr() == nil {
		return
	}
	s.mu.Lock()
	delete(s.udps, pc.LocalAddr().String())
	s.mu.Unlock()
}

func (s *Server) serveSOCKSUDP(c net.Conn, br *bufio.Reader, dest socksDest) {
	_ = c.SetReadDeadline(time.Time{})
	started := time.Now()
	sess := s.beginSession()
	info := dest.info()
	info.Command = model.SOCKSCmdUDP
	sess.via = dest.via
	sess.socks = info

	var remote string
	if ra := c.RemoteAddr(); ra != nil {
		remote = ra.String()
	}
	client := clientIP(remote)
	if err := s.gate.acquire(client, sess.spec.Proxy.Admission); err != nil {
		s.metrics.reject("admission")
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepGeneral)
		return
	}
	defer s.gate.release(client)
	s.metrics.accept()

	controlIP, err := unicastControlIP(c.LocalAddr())
	if err != nil {
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepGeneral)
		return
	}

	pc, err := s.listenUDP(controlIP)
	if err != nil {
		s.capture(socksFlow(dest, info, "listen", started), sess)
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepGeneral)
		return
	}
	s.trackUDP(pc)
	defer func() {
		s.untrackUDP(pc)
		_ = pc.Close()
	}()
	if !s.accepting.Load() {
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepGeneral)
		return
	}

	_, bndPortStr, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepGeneral)
		return
	}
	bndPort, err := strconv.Atoi(bndPortStr)
	if err != nil {
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepGeneral)
		return
	}
	info.BND = net.JoinHostPort(controlIP.String(), bndPortStr)

	if err := writeSOCKS5ReplyAddr(c, socks5RepSuccess, controlIP, bndPort); err != nil {
		return
	}
	s.metrics.socks("ok")

	sessionTO := sess.spec.Proxy.Admission.SessionTimeout
	if sessionTO <= 0 {
		sessionTO = defaultSessionTimeout
	}
	_ = c.SetDeadline(time.Now().Add(sessionTO))

	st := &udpRelayState{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.relaySOCKSUDP(pc, controlIP, info, sess, st)
	}()

	r := io.Reader(c)
	if br != nil {
		r = br
	}
	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		_, _ = io.Copy(io.Discard, r)
	}()
	select {
	case <-copyDone:
	case <-done:
	case <-s.ctx.Done():
	}
	_ = pc.Close()
	<-done

	f := socksFlow(dest, info, "", started)
	f.Truncated = st.truncated
	s.capture(f, sess)
	s.metrics.session("ok")
}

type udpRelayState struct {
	truncated bool
}

func (s *Server) relaySOCKSUDP(pc net.PacketConn, listenIP net.IP, info *model.SOCKSInfo, sess *ruleSession, st *udpRelayState) {
	ad := sess.spec.Proxy.Admission
	sessionEnd := time.Now().Add(ad.SessionTimeout)
	if ad.SessionTimeout <= 0 {
		sessionEnd = time.Now().Add(defaultSessionTimeout)
	}
	idle := ad.IdleTimeout
	if idle <= 0 {
		idle = defaultIdleTimeout
	}
	maxIn := ad.MaxInFlightBytes
	if maxIn <= 0 {
		maxIn = defaultMaxInFlightB
	}

	buf := make([]byte, socksUDPReadBuf)
	enc := make([]byte, 0, 64)
	pins := make(map[string]udpNamePin)
	origins := make(map[string]struct{})
	var client net.Addr
	var inboundN int
	var inboundB int64
	var datagrams int
	var lastDest string
	lastRelay := time.Now()

	for {
		dl := lastRelay.Add(idle)
		if dl.After(sessionEnd) {
			dl = sessionEnd
		}
		_ = pc.SetReadDeadline(dl)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		if n <= 0 || from == nil {
			continue
		}
		pkt := buf[:n]
		if client == nil {
			client = copyUDPAddr(from)
			fwd, destName, destAddr := s.forwardSOCKSUDPClient(pc, pkt, listenIP, sess, pins)
			if fwd {
				datagrams++
				lastDest = destName
				origins[udpEndpointKey(destAddr)] = struct{}{}
				lastRelay = time.Now()
			}
			continue
		}
		if sameUDPEndpoint(from, client) {
			fwd, destName, destAddr := s.forwardSOCKSUDPClient(pc, pkt, listenIP, sess, pins)
			if fwd {
				datagrams++
				lastDest = destName
				origins[udpEndpointKey(destAddr)] = struct{}{}
				lastRelay = time.Now()
			}
			continue
		}
		if _, ok := origins[udpEndpointKey(from)]; !ok {
			continue // not the pinned client and not a dest we wrote to
		}
		// inbound origin → client
		if n > socksUDPMaxPayload {
			continue
		}
		if inboundN >= socksUDPMaxDatagrams || inboundB+int64(n) > maxIn {
			st.truncated = true
			continue
		}
		enc = encodeSOCKSUDP(enc[:0], from, pkt)
		if len(enc) == 0 {
			continue
		}
		if _, werr := pc.WriteTo(enc, client); werr != nil {
			continue
		}
		inboundN++
		inboundB += int64(n)
		datagrams++
		lastRelay = time.Now()
	}

	if info != nil {
		info.Datagrams = datagrams
		info.LastDest = lastDest
	}
}

// udpNamePin caches the first allowed IP for a domain dest (no second resolve).
type udpNamePin struct {
	ip   net.IP
	deny bool
}

func (s *Server) forwardSOCKSUDPClient(pc net.PacketConn, pkt []byte, listenIP net.IP, sess *ruleSession, pins map[string]udpNamePin) (bool, string, net.Addr) {
	host, port, data, ok := parseSOCKSUDP(pkt)
	if !ok {
		return false, "", nil
	}
	if len(data) > socksUDPMaxPayload {
		return false, "", nil
	}
	ip, deny := s.selectUDPDest(host, port, listenIP, sess, pins)
	if deny || ip == nil {
		s.metrics.reject("target_denied")
		return false, "", nil
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return false, "", nil
	}
	res := resolved{Host: host, Port: port, Selected: ip, All: []net.IP{ip}}
	if s.isHairpin(res, sess.spec) {
		s.metrics.reject("target_denied")
		return false, "", nil
	}
	addr := &net.UDPAddr{IP: ip, Port: p}
	if _, err := pc.WriteTo(data, addr); err != nil {
		return false, "", nil
	}
	return true, net.JoinHostPort(host, port), addr
}

func (s *Server) selectUDPDest(host, port string, listenIP net.IP, sess *ruleSession, pins map[string]udpNamePin) (net.IP, bool) {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" || port == "" {
		return nil, true
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if denyIP(sess.spec.Proxy.Targets, ip) || udpFamilyMismatch(listenIP, ip) {
			return nil, true
		}
		return ip, false
	}

	key := strings.ToLower(host)
	if pin, ok := pins[key]; ok {
		return pin.ip, pin.deny
	}
	upTO := sess.spec.Proxy.Admission.UpstreamTimeout
	if upTO <= 0 {
		upTO = defaultUpstreamTimeout
	}
	ctx, cancel := context.WithTimeout(s.ctx, upTO)
	defer cancel()
	res, err := resolveThenGuard(ctx, s.resolver, sess.spec.Proxy.Targets, host, port)
	if err != nil {
		pins[key] = udpNamePin{deny: true}
		return nil, true
	}
	ip := pickUDPIP(res, listenIP)
	if ip == nil {
		pins[key] = udpNamePin{deny: true}
		return nil, true
	}
	pins[key] = udpNamePin{ip: append(net.IP(nil), ip...)}
	return pins[key].ip, false
}

func pickUDPIP(res resolved, listenIP net.IP) net.IP {
	if listenIP == nil {
		return nil
	}
	want4 := listenIP.To4() != nil
	for _, a := range res.All {
		if a == nil {
			continue
		}
		if (a.To4() != nil) != want4 {
			continue
		}
		if v4 := a.To4(); v4 != nil {
			return v4
		}
		return a
	}
	return nil
}

func udpFamilyMismatch(listenIP, dest net.IP) bool {
	if listenIP == nil || dest == nil {
		return true
	}
	return (listenIP.To4() != nil) != (dest.To4() != nil)
}

func parseSOCKSUDP(pkt []byte) (host, port string, data []byte, ok bool) {
	if len(pkt) < 4 {
		return "", "", nil, false
	}
	if pkt[0] != 0 || pkt[1] != 0 {
		return "", "", nil, false
	}
	if pkt[2] != 0 {
		return "", "", nil, false // FRAG ≠ 0; no reassembly
	}
	host, port, data, err := parseSOCKS5AddrBytes(pkt[3:])
	if err != nil {
		return "", "", nil, false
	}
	return host, port, data, true
}

func parseSOCKS5AddrBytes(p []byte) (host, port string, rest []byte, err error) {
	if len(p) < 1 {
		return "", "", nil, errSOCKSATYP
	}
	atyp := p[0]
	p = p[1:]
	switch atyp {
	case socks5ATYPIPv4:
		if len(p) < 6 {
			return "", "", nil, io.ErrUnexpectedEOF
		}
		host = net.IP(p[:4]).String()
		p = p[4:]
	case socks5ATYPIPv6:
		if len(p) < 18 {
			return "", "", nil, io.ErrUnexpectedEOF
		}
		host = net.IP(p[:16]).String()
		p = p[16:]
	case socks5ATYPDomain:
		if len(p) < 1 {
			return "", "", nil, io.ErrUnexpectedEOF
		}
		n := int(p[0])
		if n == 0 {
			return "", "", nil, errSOCKSATYP
		}
		p = p[1:]
		if len(p) < n+2 {
			return "", "", nil, io.ErrUnexpectedEOF
		}
		host = string(p[:n])
		p = p[n:]
	default:
		return "", "", nil, errSOCKSATYP
	}
	port = strconv.Itoa(int(binary.BigEndian.Uint16(p[:2])))
	return host, port, p[2:], nil
}

func encodeSOCKSUDP(dst []byte, from net.Addr, data []byte) []byte {
	ip, port, ok := splitIPPort(from)
	if !ok {
		return dst
	}
	dst = append(dst, 0, 0, 0) // RSV RSV FRAG
	if v4 := ip.To4(); v4 != nil {
		dst = append(dst, socks5ATYPIPv4)
		dst = append(dst, v4...)
	} else if v6 := ip.To16(); v6 != nil {
		dst = append(dst, socks5ATYPIPv6)
		dst = append(dst, v6...)
	} else {
		return dst[:0]
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	dst = append(dst, pb[:]...)
	return append(dst, data...)
}

func sameUDPEndpoint(a, b net.Addr) bool {
	if a == nil || b == nil {
		return false
	}
	return sameEndpoint(a.String(), b.String())
}

func udpEndpointKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	ip, port, ok := splitIPPort(addr)
	if !ok {
		return addr.String()
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}

func copyUDPAddr(addr net.Addr) net.Addr {
	ip, port, ok := splitIPPort(addr)
	if !ok {
		return addr
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.UDPAddr{IP: append(net.IP(nil), v4...), Port: port}
	}
	return &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: port}
}

package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func (s *Server) socksAcceptBind() bool {
	return withSpecDefaults(s.liveSpec()).Listeners.Proxy.AcceptBind
}

func (s *Server) listenBind(controlIP net.IP) (net.Listener, error) {
	if s != nil && s.listenFn != nil {
		return s.listenFn(controlIP)
	}
	return listenEphemeralTCP(controlIP)
}

func (s *Server) trackBind(ln net.Listener) {
	if s == nil || ln == nil {
		return
	}
	s.mu.Lock()
	if s.binds == nil {
		s.binds = make(map[string]net.Listener)
	}
	s.binds[ln.Addr().String()] = ln
	s.mu.Unlock()
}

func (s *Server) untrackBind(ln net.Listener) {
	if s == nil || ln == nil {
		return
	}
	s.mu.Lock()
	delete(s.binds, ln.Addr().String())
	s.mu.Unlock()
}

func (s *Server) liveBindAddrs() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.binds))
	for a := range s.binds {
		out = append(out, a)
	}
	return out
}

func (s *Server) closeBinds() {
	if s == nil {
		return
	}
	s.mu.Lock()
	lns := make([]net.Listener, 0, len(s.binds))
	for _, ln := range s.binds {
		lns = append(lns, ln)
	}
	s.mu.Unlock()
	for _, ln := range lns {
		_ = ln.Close()
	}
}

func (s *Server) serveSOCKSBind(c net.Conn, br *bufio.Reader, dest socksDest) {
	_ = c.SetReadDeadline(time.Time{})
	started := time.Now()
	sess := s.beginSession()
	info := dest.info()
	info.Command = model.SOCKSCmdBind
	sess.via = dest.via
	sess.socks = info

	if socksUnspecifiedDST(dest.host, dest.port) {
		s.metrics.reject("target_denied")
		s.capture(socksFlow(dest, info, string(domainerr.CodeTargetDenied), started), sess)
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepNotAllowed)
		return
	}

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

	res, err := func() (resolved, error) {
		upTO := sess.spec.Proxy.Admission.UpstreamTimeout
		if upTO <= 0 {
			upTO = defaultUpstreamTimeout
		}
		ctx, cancel := context.WithTimeout(s.ctx, upTO)
		defer cancel()
		return resolveThenGuard(ctx, s.resolver, sess.spec.Proxy.Targets, dest.host, dest.port)
	}()
	if err != nil {
		if isDNS(err) {
			s.capture(socksFlow(dest, info, "dns", started), sess)
			s.metrics.socks("denied")
			_ = replySOCKS(c, dest, socks5RepHostUnreach)
			return
		}
		s.metrics.reject("target_denied")
		s.capture(socksFlow(dest, info, string(domainerr.CodeTargetDenied), started), sess)
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepNotAllowed)
		return
	}

	controlIP, err := unicastControlIP(c.LocalAddr())
	if err != nil {
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepGeneral)
		return
	}
	if dest.ver == 4 && controlIP.To4() == nil {
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepGeneral)
		return
	}

	ln, err := s.listenBind(controlIP)
	if err != nil {
		s.capture(socksFlow(dest, info, "listen", started), sess)
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepGeneral)
		return
	}
	s.trackBind(ln)
	defer func() {
		s.untrackBind(ln)
		_ = ln.Close()
	}()
	if !s.accepting.Load() {
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepGeneral)
		return
	}

	_, bndPortStr, err := net.SplitHostPort(ln.Addr().String())
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

	if err := writeSOCKSBindReply(c, dest, socks5RepSuccess, controlIP, bndPort); err != nil {
		return
	}

	sessionTO := sess.spec.Proxy.Admission.SessionTimeout
	if sessionTO <= 0 {
		sessionTO = defaultSessionTimeout
	}
	if tl, ok := ln.(*net.TCPListener); ok {
		_ = tl.SetDeadline(time.Now().Add(sessionTO))
	}

	inbound, err := ln.Accept()
	if err != nil {
		s.capture(socksFlow(dest, info, "accept", started), sess)
		s.metrics.socks("denied")
		_ = writeSOCKSBindReply(c, dest, socks5RepGeneral, nil, 0)
		return
	}
	s.track(inbound)
	defer s.untrack(inbound)
	defer func() { _ = inbound.Close() }()

	peerIP, peerPort, ok := splitIPPort(inbound.RemoteAddr())
	if !ok || denyIP(sess.spec.Proxy.Targets, peerIP) || !ipInResolved(peerIP, res) {
		s.metrics.reject("target_denied")
		s.capture(socksFlow(dest, info, string(domainerr.CodeTargetDenied), started), sess)
		s.metrics.socks("denied")
		_ = writeSOCKSBindReply(c, dest, socks5RepNotAllowed, nil, 0)
		return
	}

	if err := writeSOCKSBindReply(c, dest, socks5RepSuccess, peerIP, peerPort); err != nil {
		return
	}
	s.metrics.socks("ok")
	s.capture(socksFlow(dest, info, "", started), sess)
	s.metrics.session("ok")
	s.tunnel(c, leftoverRW(c, br), inbound, sess.spec.Proxy.Admission)
}

func checkBindListenIP(ip net.IP) error {
	if ip == nil || ip.IsUnspecified() {
		return fmt.Errorf("proxy: BIND listen IP is unspecified")
	}
	targets := model.TargetsSpec{
		DenyCloudMetadata: true,
		DenyLinkLocal:     true,
		AllowLoopback:     true,
	}
	if denyIP(targets, ip) {
		return fmt.Errorf("proxy: BIND listen IP denied")
	}
	return nil
}

func unicastControlIP(addr net.Addr) (net.IP, error) {
	if addr == nil {
		return nil, fmt.Errorf("proxy: missing control LocalAddr")
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, fmt.Errorf("proxy: control LocalAddr: %w", err)
	}
	ip := net.ParseIP(host)
	if err := checkBindListenIP(ip); err != nil {
		return nil, err
	}
	if v4 := ip.To4(); v4 != nil {
		return v4, nil
	}
	return ip, nil
}

func socksUnspecifiedDST(host, port string) bool {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" || port == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

func ipInResolved(ip net.IP, res resolved) bool {
	if ip == nil {
		return false
	}
	for _, a := range res.All {
		if a != nil && a.Equal(ip) {
			return true
		}
	}
	return false
}

func splitIPPort(addr net.Addr) (net.IP, int, bool) {
	if addr == nil {
		return nil, 0, false
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, 0, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, false
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, false
	}
	return ip, p, true
}

func writeSOCKSBindReply(c net.Conn, dest socksDest, rep byte, ip net.IP, port int) error {
	if dest.ver == 4 {
		cd := byte(socks4Granted)
		if rep != socks5RepSuccess {
			cd = socks4Rejected
		}
		return writeSOCKS4ReplyAddr(c, cd, ip, port)
	}
	return writeSOCKS5ReplyAddr(c, rep, ip, port)
}

func writeSOCKS5ReplyAddr(w io.Writer, rep byte, ip net.IP, port int) error {
	if ip != nil {
		if v4 := ip.To4(); v4 != nil {
			msg := []byte{socks5Ver, rep, 0x00, socks5ATYPIPv4, 0, 0, 0, 0, 0, 0}
			copy(msg[4:8], v4)
			binary.BigEndian.PutUint16(msg[8:10], uint16(port))
			_, err := w.Write(msg)
			return err
		}
		if v6 := ip.To16(); v6 != nil {
			msg := make([]byte, 22)
			msg[0] = socks5Ver
			msg[1] = rep
			msg[3] = socks5ATYPIPv6
			copy(msg[4:20], v6)
			binary.BigEndian.PutUint16(msg[20:22], uint16(port))
			_, err := w.Write(msg)
			return err
		}
	}
	return writeSOCKS5Reply(w, rep, socks5ATYPIPv4)
}

func writeSOCKS4ReplyAddr(w io.Writer, cd byte, ip net.IP, port int) error {
	msg := []byte{0, cd, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(msg[2:4], uint16(port))
	if v4 := ip.To4(); v4 != nil {
		copy(msg[4:8], v4)
	}
	_, err := w.Write(msg)
	return err
}

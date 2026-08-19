package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

const (
	socks5Ver            = 0x05
	socks4Ver            = 0x04
	socks5NoAuth         = 0x00
	socks5NoAcceptable   = 0xff
	socks5CmdConnect     = 0x01
	socks5ATYPIPv4       = 0x01
	socks5ATYPDomain     = 0x03
	socks5ATYPIPv6       = 0x04
	socks5RepSuccess     = 0x00
	socks5RepGeneral     = 0x01
	socks5RepNotAllowed  = 0x02
	socks5RepHostUnreach = 0x04
	socks5RepRefused     = 0x05
	socks5RepCommand     = 0x07
	socks5RepATYP        = 0x08
	socks4Granted        = 90
	socks4Rejected       = 91
	socks4UseridMax      = 256
	socksATYPIPv4        = "ipv4"
	socksATYPIPv6        = "ipv6"
	socksATYPDomain      = "domain"
	socksCmdConnect      = "connect"
)

var errSOCKSATYP = errors.New("socks address type not supported")

type socksDest struct {
	host    string
	port    string
	atyp    string
	bndATYP byte
	via     string
	proto   string
	ver     int
}

func (d socksDest) info() *model.SOCKSInfo {
	return &model.SOCKSInfo{
		Version: d.ver,
		ATYP:    d.atyp,
		Dest:    net.JoinHostPort(d.host, d.port),
		Command: socksCmdConnect,
	}
}

func (s *Server) serveSOCKS5(c net.Conn) {
	if c == nil {
		return
	}
	s.beginHijacked()
	defer s.endHijacked()
	s.track(c)
	defer s.untrack(c)
	defer func() { _ = c.Close() }()

	br, err := s.socksReader(c)
	if err != nil {
		return
	}
	ver, err := br.ReadByte()
	if err != nil {
		return
	}
	if ver != socks5Ver {
		return
	}
	nmethods, err := br.ReadByte()
	if err != nil {
		return
	}
	if nmethods == 0 {
		s.metrics.reject("socks_auth")
		s.metrics.socks("auth")
		return
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if !socks5OffersNoAuth(methods) {
		_, _ = c.Write([]byte{socks5Ver, socks5NoAcceptable})
		s.metrics.reject("socks_auth")
		s.metrics.socks("auth")
		return
	}
	if _, err := c.Write([]byte{socks5Ver, socks5NoAuth}); err != nil {
		return
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	if hdr[0] != socks5Ver {
		return
	}
	if hdr[2] != 0 {
		_ = writeSOCKS5Reply(c, socks5RepGeneral, socks5ATYPIPv4)
		return
	}
	if hdr[1] != socks5CmdConnect {
		_ = writeSOCKS5Reply(c, socks5RepCommand, socks5ATYPIPv4)
		s.metrics.reject("socks_command")
		s.metrics.socks("command")
		return
	}
	host, port, atyp, bnd, err := readSOCKS5Addr(br, hdr[3])
	if err != nil {
		if errors.Is(err, errSOCKSATYP) {
			_ = writeSOCKS5Reply(c, socks5RepATYP, socks5ATYPIPv4)
			s.metrics.socks("command")
		}
		return
	}
	s.serveSOCKSConnect(c, br, socksDest{
		host:    host,
		port:    port,
		atyp:    atyp,
		bndATYP: bnd,
		via:     "socks5",
		proto:   model.FlowProtocolSOCKS5,
		ver:     5,
	})
}

func (s *Server) serveSOCKS4(c net.Conn) {
	if c == nil {
		return
	}
	s.beginHijacked()
	defer s.endHijacked()
	s.track(c)
	defer s.untrack(c)
	defer func() { _ = c.Close() }()

	br, err := s.socksReader(c)
	if err != nil {
		return
	}
	hdr := make([]byte, 8) // VN CD PORT(2) IP(4); VN is peeked
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	if hdr[0] != socks4Ver {
		return
	}
	if hdr[1] != 1 {
		_ = writeSOCKS4Reply(c, socks4Rejected)
		s.metrics.reject("socks_command")
		s.metrics.socks("command")
		return
	}
	if _, err := readNUL(br, socks4UseridMax); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(hdr[2:4])
	ip := net.IPv4(hdr[4], hdr[5], hdr[6], hdr[7])
	host := ip.String()
	atyp := socksATYPIPv4
	if hdr[4] == 0 && hdr[5] == 0 && hdr[6] == 0 && hdr[7] != 0 {
		name, err := readNUL(br, 255)
		if err != nil || len(name) == 0 {
			_ = writeSOCKS4Reply(c, socks4Rejected)
			return
		}
		host = string(name)
		atyp = socksATYPDomain
	}
	s.serveSOCKSConnect(c, br, socksDest{
		host:    host,
		port:    strconv.Itoa(int(port)),
		atyp:    atyp,
		bndATYP: socks5ATYPIPv4,
		via:     "socks4",
		proto:   model.FlowProtocolSOCKS4,
		ver:     4,
	})
}

func (s *Server) socksReader(c net.Conn) (*bufio.Reader, error) {
	spec := withSpecDefaults(s.liveSpec())
	ht := spec.Proxy.Admission.HeaderTimeout
	if ht <= 0 {
		ht = defaultHeaderTimeout
	}
	if err := c.SetReadDeadline(time.Now().Add(ht)); err != nil {
		return nil, err
	}
	return bufio.NewReader(c), nil
}

func (s *Server) serveSOCKSConnect(c net.Conn, br *bufio.Reader, dest socksDest) {
	_ = c.SetReadDeadline(time.Time{})
	started := time.Now()
	sess := s.beginSession()
	info := dest.info()
	sess.via = dest.via
	sess.socks = info

	var remote string
	if ra := c.RemoteAddr(); ra != nil {
		remote = ra.String()
	}
	ip := clientIP(remote)
	if err := s.gate.acquire(ip, sess.spec.Proxy.Admission); err != nil {
		s.metrics.reject("admission")
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepGeneral)
		return
	}
	defer s.gate.release(ip)
	s.metrics.accept()

	upTO := sess.spec.Proxy.Admission.UpstreamTimeout
	if upTO <= 0 {
		upTO = defaultUpstreamTimeout
	}
	ctx, cancel := context.WithTimeout(s.ctx, upTO)
	defer cancel()

	res, err := resolveThenGuard(ctx, s.resolver, sess.spec.Proxy.Targets, dest.host, dest.port)
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
	if s.isHairpin(res, sess.spec) {
		s.metrics.reject("target_denied")
		s.capture(socksFlow(dest, info, string(domainerr.CodeTargetDenied), started), sess)
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepNotAllowed)
		return
	}

	up, err := s.dialPinnedTO(ctx, "tcp", pinnedAddr(res.Selected, res.Port), sess.spec.Proxy.Admission.DialTimeout)
	if err != nil {
		s.capture(socksFlow(dest, info, "dial", started), sess)
		s.metrics.socks("denied")
		_ = replySOCKS(c, dest, socks5RepRefused)
		return
	}
	s.track(up)
	defer s.untrack(up)
	defer func() { _ = up.Close() }()

	if err := replySOCKS(c, dest, socks5RepSuccess); err != nil {
		return
	}
	s.metrics.socks("ok")

	bufrw := leftoverRW(c, br)
	if shouldIntercept(sess.spec.TLS, dest.host, dest.port) {
		s.serveInterceptConn(c, bufrw, up, interceptMeta{
			ConnectHost: dest.host,
			Port:        dest.port,
			Res:         res,
			Started:     started,
			Via:         dest.via,
			SOCKS:       info,
		}, sess)
		return
	}
	s.capture(socksFlow(dest, info, "", started), sess)
	s.metrics.session("ok")
	s.tunnel(c, bufrw, up, sess.spec.Proxy.Admission)
}

func replySOCKS(c net.Conn, dest socksDest, rep byte) error {
	if dest.ver == 4 {
		cd := byte(socks4Granted)
		if rep != socks5RepSuccess {
			cd = socks4Rejected
		}
		return writeSOCKS4Reply(c, cd)
	}
	atyp := dest.bndATYP
	if rep == socks5RepHostUnreach || rep == socks5RepRefused {
		atyp = socks5ATYPIPv4
	}
	if atyp != socks5ATYPIPv6 {
		atyp = socks5ATYPIPv4
	}
	return writeSOCKS5Reply(c, rep, atyp)
}

func socks5OffersNoAuth(methods []byte) bool {
	for _, m := range methods {
		if m == socks5NoAuth {
			return true
		}
	}
	return false
}

func readSOCKS5Addr(br *bufio.Reader, atyp byte) (host, port, atypName string, bnd byte, err error) {
	switch atyp {
	case socks5ATYPIPv4:
		var addr [4]byte
		if _, err := io.ReadFull(br, addr[:]); err != nil {
			return "", "", "", 0, err
		}
		host = net.IP(addr[:]).String()
		atypName = socksATYPIPv4
		bnd = socks5ATYPIPv4
	case socks5ATYPIPv6:
		var addr [16]byte
		if _, err := io.ReadFull(br, addr[:]); err != nil {
			return "", "", "", 0, err
		}
		host = net.IP(addr[:]).String()
		atypName = socksATYPIPv6
		bnd = socks5ATYPIPv6
	case socks5ATYPDomain:
		n, err := br.ReadByte()
		if err != nil {
			return "", "", "", 0, err
		}
		if n == 0 {
			return "", "", "", 0, errSOCKSATYP
		}
		name := make([]byte, n)
		if _, err := io.ReadFull(br, name); err != nil {
			return "", "", "", 0, err
		}
		host = string(name)
		atypName = socksATYPDomain
		bnd = socks5ATYPIPv4
	default:
		return "", "", "", 0, errSOCKSATYP
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return "", "", "", 0, err
	}
	return host, strconv.Itoa(int(binary.BigEndian.Uint16(pb[:]))), atypName, bnd, nil
}

func writeSOCKS5Reply(w io.Writer, rep, atyp byte) error {
	if atyp == socks5ATYPIPv6 {
		msg := make([]byte, 22)
		msg[0] = socks5Ver
		msg[1] = rep
		msg[3] = socks5ATYPIPv6
		_, err := w.Write(msg)
		return err
	}
	_, err := w.Write([]byte{socks5Ver, rep, 0x00, socks5ATYPIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func writeSOCKS4Reply(w io.Writer, cd byte) error {
	_, err := w.Write([]byte{0, cd, 0, 0, 0, 0, 0, 0})
	return err
}

func readNUL(r *bufio.Reader, max int) ([]byte, error) {
	var b []byte
	for {
		if len(b) >= max {
			return nil, io.ErrUnexpectedEOF
		}
		c, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if c == 0 {
			return b, nil
		}
		b = append(b, c)
	}
}

func leftoverRW(c net.Conn, br *bufio.Reader) *bufio.ReadWriter {
	if br == nil || br.Buffered() == 0 {
		return nil
	}
	return bufio.NewReadWriter(br, bufio.NewWriter(c))
}

func socksFlow(dest socksDest, info *model.SOCKSInfo, ferr string, started time.Time) *model.Flow {
	state := model.FlowStateCompleted
	if ferr != "" {
		state = model.FlowStateError
	}
	return &model.Flow{
		StartedAt:   started.UTC(),
		CompletedAt: time.Now().UTC(),
		State:       state,
		Method:      http.MethodConnect,
		Host:        dest.host,
		Protocol:    dest.proto,
		Error:       ferr,
		Intercepted: false,
		Via:         dest.via,
		SOCKS:       info,
	}
}

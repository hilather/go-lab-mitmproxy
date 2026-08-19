//go:build linux

package proxy

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

const origDestSupported = true

const (
	soOriginalDst     = 80
	ip6tSoOriginalDst = 80
	solIPv6           = 41
)

func getOriginalDst(c net.Conn) (net.IP, int, error) {
	tcp := tcpConnOf(c)
	if tcp == nil {
		return nil, 0, errOrigDestUnsupported
	}
	rc, err := tcp.SyscallConn()
	if err != nil {
		return nil, 0, err
	}
	var (
		ip      net.IP
		port    int
		sockErr error
	)
	if err := rc.Control(func(fd uintptr) {
		ip, port, sockErr = origDstAt(int(fd), tcp.LocalAddr())
	}); err != nil {
		return nil, 0, err
	}
	if sockErr != nil {
		return nil, 0, sockErr
	}
	if ip == nil {
		return nil, 0, errOrigDestUnsupported
	}
	return ip, port, nil
}

func origDstAt(fd int, local net.Addr) (net.IP, int, error) {
	if isIPv4Local(local) {
		if ip, port, err := origDst4(fd); err == nil {
			return ip, port, nil
		}
		return origDst6(fd)
	}
	if ip, port, err := origDst6(fd); err == nil {
		return ip, port, nil
	}
	return origDst4(fd)
}

func isIPv4Local(addr net.Addr) bool {
	ta, ok := addr.(*net.TCPAddr)
	if !ok || ta.IP == nil {
		return true
	}
	return ta.IP.To4() != nil
}

func origDst4(fd int) (net.IP, int, error) {
	var addr syscall.RawSockaddrInet4
	l := uint32(unsafe.Sizeof(addr))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_IP),
		uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&l)),
		0,
	)
	if errno != 0 {
		return nil, 0, errno
	}
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:]))
	return ip, port, nil
}

func origDst6(fd int) (net.IP, int, error) {
	var addr syscall.RawSockaddrInet6
	l := uint32(unsafe.Sizeof(addr))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(solIPv6),
		uintptr(ip6tSoOriginalDst),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&l)),
		0,
	)
	if errno != 0 {
		return nil, 0, errno
	}
	ip := make(net.IP, net.IPv6len)
	copy(ip, addr.Addr[:])
	port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:]))
	return ip, port, nil
}

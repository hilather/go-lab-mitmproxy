//go:build !linux

package proxy

import "net"

const origDestSupported = false

func getOriginalDst(net.Conn) (net.IP, int, error) {
	return nil, 0, errOrigDestUnsupported
}

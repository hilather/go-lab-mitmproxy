package wsx

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

const (
	OpcodeContinuation byte = 0x0
	OpcodeText         byte = 0x1
	OpcodeBinary       byte = 0x2
	OpcodeClose        byte = 0x8
	OpcodePing         byte = 0x9
	OpcodePong         byte = 0xA

	maxControlPayload = 125
	defaultMaxPayload = 32 << 20

	rsv1Bit = 0x40
	rsv2Bit = 0x20
	rsv3Bit = 0x10
)

// ErrProtocol is a RFC 6455 framing violation (control >125, bad length, …).
var ErrProtocol = errors.New("wsx: protocol error")

// ErrTooLarge is a declared payload larger than max (ReadFrame buffer cap).
// It is not a framing violation; the unread payload remains on r.
var ErrTooLarge = errors.New("wsx: frame too large")

// Frame is one RFC 6455 frame. Payload is unmasked.
type Frame struct {
	Fin         bool
	RSV1        bool
	RSV2        bool
	RSV3        bool
	Opcode      byte
	Masked      bool
	MaskKey     [4]byte // not exported on REST
	Payload     []byte  // unmasked
	CloseCode   int
	CloseReason []byte
}

// Header is the RFC 6455 header without payload. Length is the declared size.
type Header struct {
	Fin     bool
	RSV1    bool
	RSV2    bool
	RSV3    bool
	Opcode  byte
	Masked  bool
	MaskKey [4]byte
	Length  uint64
}

// OpcodeName is the stored opcode token. Unknown values are "other".
func OpcodeName(op byte) string {
	switch op {
	case OpcodeContinuation:
		return "continuation"
	case OpcodeText:
		return "text"
	case OpcodeBinary:
		return "binary"
	case OpcodeClose:
		return "close"
	case OpcodePing:
		return "ping"
	case OpcodePong:
		return "pong"
	default:
		return "other"
	}
}

func (h Header) toFrame() Frame {
	return Frame{
		Fin:     h.Fin,
		RSV1:    h.RSV1,
		RSV2:    h.RSV2,
		RSV3:    h.RSV3,
		Opcode:  h.Opcode,
		Masked:  h.Masked,
		MaskKey: h.MaskKey,
	}
}

// ReadHeader parses one frame header. Negotiated RSV bits are not a protocol
// error. Control frames larger than 125 bytes are ErrProtocol.
func ReadHeader(r io.Reader) (Header, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Header{}, err
	}
	h := Header{
		Fin:    hdr[0]&0x80 != 0,
		RSV1:   hdr[0]&rsv1Bit != 0,
		RSV2:   hdr[0]&rsv2Bit != 0,
		RSV3:   hdr[0]&rsv3Bit != 0,
		Opcode: hdr[0] & 0x0f,
		Masked: hdr[1]&0x80 != 0,
	}
	l7 := int(hdr[1] & 0x7f)
	control := h.Opcode&0x8 != 0
	if control && !h.Fin {
		return Header{}, ErrProtocol
	}
	if control && l7 > maxControlPayload {
		return Header{}, ErrProtocol
	}

	var n uint64
	switch l7 {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return Header{}, err
		}
		n = uint64(binary.BigEndian.Uint16(ext[:]))
		if n <= maxControlPayload {
			return Header{}, ErrProtocol
		}
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return Header{}, err
		}
		n = binary.BigEndian.Uint64(ext[:])
		if n&(1<<63) != 0 || n <= math.MaxUint16 {
			return Header{}, ErrProtocol
		}
	default:
		n = uint64(l7)
	}
	if control && n > maxControlPayload {
		return Header{}, ErrProtocol
	}
	h.Length = n
	if h.Masked {
		if _, err := io.ReadFull(r, h.MaskKey[:]); err != nil {
			return Header{}, err
		}
	}
	return h, nil
}

// WriteHeader writes the RFC 6455 header for payload length n, including RSV.
func WriteHeader(w io.Writer, h Header) error {
	n := h.Length
	if h.Opcode&0x8 != 0 {
		if !h.Fin {
			return ErrProtocol
		}
		if n > maxControlPayload {
			return ErrProtocol
		}
	}
	var hdr [14]byte
	b0 := h.Opcode & 0x0f
	if h.Fin {
		b0 |= 0x80
	}
	if h.RSV1 {
		b0 |= rsv1Bit
	}
	if h.RSV2 {
		b0 |= rsv2Bit
	}
	if h.RSV3 {
		b0 |= rsv3Bit
	}
	hdr[0] = b0
	off := 2
	switch {
	case n <= maxControlPayload:
		hdr[1] = byte(n)
	case n <= math.MaxUint16:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		off = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], n)
		off = 10
	}
	if h.Masked {
		hdr[1] |= 0x80
		copy(hdr[off:off+4], h.MaskKey[:])
		off += 4
	}
	_, err := w.Write(hdr[:off])
	return err
}

// TeePayload copies n wire bytes from src to dst (masking unchanged) and
// returns the unmasked prefix up to storeMax. storeMax<=0 stores nothing.
func TeePayload(dst io.Writer, src io.Reader, n uint64, masked bool, key [4]byte, storeMax int) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	var stored []byte
	buf := make([]byte, 32<<10)
	var off uint64
	for off < n {
		chunk := len(buf)
		if remain := n - off; uint64(chunk) > remain {
			chunk = int(remain)
		}
		nr, err := io.ReadFull(src, buf[:chunk])
		if nr > 0 {
			if _, werr := dst.Write(buf[:nr]); werr != nil {
				return stored, werr
			}
			if storeMax > 0 && len(stored) < storeMax {
				take := nr
				if len(stored)+take > storeMax {
					take = storeMax - len(stored)
				}
				piece := append([]byte(nil), buf[:take]...)
				if masked {
					for i := range piece {
						piece[i] ^= key[int(off+uint64(i))&3]
					}
				}
				stored = append(stored, piece...)
			}
			off += uint64(nr)
		}
		if err != nil {
			return stored, err
		}
	}
	return stored, nil
}

// ReadFrame reads one frame from r. max is the max payload to allocate;
// max<=0 uses a 32 MiB ceiling. Control frames larger than 125 bytes are
// ErrProtocol. RSV bits are preserved and are not a protocol error.
func ReadFrame(r io.Reader, max int) (Frame, error) {
	if max <= 0 {
		max = defaultMaxPayload
	}
	h, err := ReadHeader(r)
	if err != nil {
		return Frame{}, err
	}
	if h.Length > uint64(max) {
		return Frame{}, ErrTooLarge
	}
	f := h.toFrame()
	if h.Length > 0 {
		payload := make([]byte, int(h.Length))
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
		if h.Masked {
			maskInPlace(payload, h.MaskKey)
		}
		f.Payload = payload
	}
	if err := parseClose(&f); err != nil {
		return Frame{}, err
	}
	return f, nil
}

// WriteFrame writes one frame. Payload is treated as unmasked; if Masked is
// set it is masked with MaskKey on the wire. RSV bits are written unchanged.
func WriteFrame(w io.Writer, f Frame) error {
	payload := f.Payload
	if f.Opcode == OpcodeClose && len(payload) == 0 && (f.CloseCode != 0 || len(f.CloseReason) > 0) {
		payload = make([]byte, 2+len(f.CloseReason))
		binary.BigEndian.PutUint16(payload[:2], uint16(f.CloseCode))
		copy(payload[2:], f.CloseReason)
	}
	h := Header{
		Fin:     f.Fin,
		RSV1:    f.RSV1,
		RSV2:    f.RSV2,
		RSV3:    f.RSV3,
		Opcode:  f.Opcode,
		Masked:  f.Masked,
		MaskKey: f.MaskKey,
		Length:  uint64(len(payload)),
	}
	if err := WriteHeader(w, h); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	if !f.Masked {
		_, err := w.Write(payload)
		return err
	}
	masked := append([]byte(nil), payload...)
	maskInPlace(masked, f.MaskKey)
	_, err := w.Write(masked)
	return err
}

func parseClose(f *Frame) error {
	if f.Opcode != OpcodeClose {
		return nil
	}
	payload := f.Payload
	if len(payload) == 1 {
		return ErrProtocol
	}
	if len(payload) >= 2 {
		f.CloseCode = int(binary.BigEndian.Uint16(payload[:2]))
		if len(payload) > 2 {
			f.CloseReason = append([]byte(nil), payload[2:]...)
		}
	}
	return nil
}

func maskInPlace(b []byte, key [4]byte) {
	for i := range b {
		b[i] ^= key[i&3]
	}
}

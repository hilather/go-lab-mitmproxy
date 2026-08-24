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
)

// ErrProtocol is a RFC 6455 framing violation (control >125, bad length, …).
var ErrProtocol = errors.New("wsx: protocol error")

// ErrTooLarge is a declared payload larger than max.
var ErrTooLarge = errors.New("wsx: frame too large")

// Frame is one RFC 6455 frame. Payload is unmasked.
type Frame struct {
	Fin         bool
	Opcode      byte
	Masked      bool
	MaskKey     [4]byte // not exported on REST
	Payload     []byte  // unmasked
	CloseCode   int
	CloseReason []byte
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

// ReadFrame reads one frame from r. max is the max payload to allocate;
// max<=0 uses a 32 MiB ceiling. Control frames larger than 125 bytes are
// ErrProtocol.
func ReadFrame(r io.Reader, max int) (Frame, error) {
	if max <= 0 {
		max = defaultMaxPayload
	}
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	fin := hdr[0]&0x80 != 0
	opcode := hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	l7 := int(hdr[1] & 0x7f)
	control := opcode&0x8 != 0
	if control && !fin {
		return Frame{}, ErrProtocol
	}
	if control && l7 > maxControlPayload {
		return Frame{}, ErrProtocol
	}

	var n uint64
	switch l7 {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return Frame{}, err
		}
		n = uint64(binary.BigEndian.Uint16(ext[:]))
		if n <= maxControlPayload {
			return Frame{}, ErrProtocol
		}
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return Frame{}, err
		}
		n = binary.BigEndian.Uint64(ext[:])
		if n&(1<<63) != 0 || n <= math.MaxUint16 {
			return Frame{}, ErrProtocol
		}
	default:
		n = uint64(l7)
	}
	if control && n > maxControlPayload {
		return Frame{}, ErrProtocol
	}
	if n > uint64(max) {
		return Frame{}, ErrTooLarge
	}

	var key [4]byte
	if masked {
		if _, err := io.ReadFull(r, key[:]); err != nil {
			return Frame{}, err
		}
	}

	var payload []byte
	if n > 0 {
		payload = make([]byte, int(n))
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
		if masked {
			maskInPlace(payload, key)
		}
	}

	f := Frame{
		Fin:     fin,
		Opcode:  opcode,
		Masked:  masked,
		MaskKey: key,
		Payload: payload,
	}
	if opcode == OpcodeClose {
		if len(payload) == 1 {
			return Frame{}, ErrProtocol
		}
		if len(payload) >= 2 {
			f.CloseCode = int(binary.BigEndian.Uint16(payload[:2]))
			if len(payload) > 2 {
				f.CloseReason = append([]byte(nil), payload[2:]...)
			}
		}
	}
	return f, nil
}

// WriteFrame writes one frame. Payload is treated as unmasked; if Masked is
// set it is masked with MaskKey on the wire.
func WriteFrame(w io.Writer, f Frame) error {
	payload := f.Payload
	if f.Opcode == OpcodeClose && len(payload) == 0 && (f.CloseCode != 0 || len(f.CloseReason) > 0) {
		payload = make([]byte, 2+len(f.CloseReason))
		binary.BigEndian.PutUint16(payload[:2], uint16(f.CloseCode))
		copy(payload[2:], f.CloseReason)
	}
	n := len(payload)
	if f.Opcode&0x8 != 0 {
		if !f.Fin {
			return ErrProtocol
		}
		if n > maxControlPayload {
			return ErrProtocol
		}
	}

	var hdr [14]byte
	b0 := f.Opcode & 0x0f
	if f.Fin {
		b0 |= 0x80
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
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		off = 10
	}
	if f.Masked {
		hdr[1] |= 0x80
		copy(hdr[off:off+4], f.MaskKey[:])
		off += 4
	}
	if _, err := w.Write(hdr[:off]); err != nil {
		return err
	}
	if n == 0 {
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

func maskInPlace(b []byte, key [4]byte) {
	for i := range b {
		b[i] ^= key[i&3]
	}
}

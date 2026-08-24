package wsx

import (
	"bytes"
	"io"
	"testing"
)

func FuzzReadFrame(f *testing.F) {
	var text bytes.Buffer
	_ = WriteFrame(&text, Frame{Fin: true, Opcode: OpcodeText, Masked: true, MaskKey: [4]byte{9, 8, 7, 6}, Payload: []byte("hi")})
	f.Add(text.Bytes())
	var ping bytes.Buffer
	_ = WriteFrame(&ping, Frame{Fin: true, Opcode: OpcodePing, Payload: []byte("p")})
	f.Add(ping.Bytes())
	var closeBuf bytes.Buffer
	_ = WriteFrame(&closeBuf, Frame{Fin: true, Opcode: OpcodeClose, CloseCode: 1000})
	f.Add(closeBuf.Bytes())
	f.Add([]byte{0x89, 126, 0, 200})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			data = data[:64*1024]
		}
		_, err := ReadFrame(bytes.NewReader(data), 1<<20)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF && err != ErrProtocol && err != ErrTooLarge {
			// any other error is still fine; must not panic
			return
		}
	})
}

package wsx

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestRoundTripTextMasked(t *testing.T) {
	in := Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{1, 2, 3, 4},
		Payload: []byte("hello"),
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Fin || got.Opcode != OpcodeText || !got.Masked || string(got.Payload) != "hello" {
		t.Fatalf("got %+v", got)
	}
	if got.MaskKey != in.MaskKey {
		t.Fatalf("mask %+v", got.MaskKey)
	}
}

func TestRoundTripBinaryUnmasked(t *testing.T) {
	in := Frame{Fin: true, Opcode: OpcodeBinary, Payload: []byte{0x00, 0xff, 0x7f}}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Masked || !bytes.Equal(got.Payload, in.Payload) || OpcodeName(got.Opcode) != "binary" {
		t.Fatalf("got %+v", got)
	}
}

func TestRoundTripCloseCode(t *testing.T) {
	in := Frame{Fin: true, Opcode: OpcodeClose, CloseCode: 1000, CloseReason: []byte("bye")}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.CloseCode != 1000 || string(got.CloseReason) != "bye" || string(got.Payload) != "\x03\xe8bye" {
		t.Fatalf("got %+v payload=%q", got, got.Payload)
	}
}

func TestControlTooLarge(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x89, 126, 0, 126}) // ping, 7-bit len 126
	if _, err := ReadFrame(&buf, 0); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v", err)
	}
}

func TestWriteControlTooLarge(t *testing.T) {
	err := WriteFrame(io.Discard, Frame{Fin: true, Opcode: OpcodePing, Payload: bytes.Repeat([]byte("x"), 126)})
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v", err)
	}
}

func TestExtendedLengthRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), 200)
	in := Frame{Fin: true, Opcode: OpcodeBinary, Payload: payload}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("len=%d", len(got.Payload))
	}
}

func TestMaxPayload(t *testing.T) {
	in := Frame{Fin: true, Opcode: OpcodeText, Payload: []byte("abcd")}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(&buf, 3); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err=%v", err)
	}
}

func TestCloseOneBytePayload(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Frame{Fin: true, Opcode: OpcodeBinary, Payload: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	// Rebuild as a 1-byte close by patching opcode.
	raw := buf.Bytes()
	raw[0] = 0x88
	if _, err := ReadFrame(bytes.NewReader(raw), 0); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v", err)
	}
}

func TestOpcodeName(t *testing.T) {
	if OpcodeName(3) != "other" || OpcodeName(OpcodePong) != "pong" {
		t.Fatal(OpcodeName(3), OpcodeName(OpcodePong))
	}
}

func TestFragmentedControlRejected(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x09, 0x00}) // ping, FIN=0
	if _, err := ReadFrame(&buf, 0); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v", err)
	}
}

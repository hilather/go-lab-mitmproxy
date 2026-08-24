package wsx

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestRoundTripRSV1(t *testing.T) {
	in := Frame{
		Fin:     true,
		RSV1:    true,
		Opcode:  OpcodeBinary,
		Masked:  true,
		MaskKey: [4]byte{9, 8, 7, 6},
		Payload: []byte("deflate-shaped"),
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if raw[0]&0x40 == 0 {
		t.Fatalf("wire missing RSV1: 0x%02x", raw[0])
	}
	got, err := ReadFrame(&buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !got.RSV1 || got.RSV2 || got.RSV3 || got.Opcode != OpcodeBinary || string(got.Payload) != "deflate-shaped" {
		t.Fatalf("got %+v", got)
	}
}

func TestTeePayloadForwardsFullStoresPrefix(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 200)
	in := Frame{Fin: true, Opcode: OpcodeBinary, Payload: payload}
	var wire bytes.Buffer
	if err := WriteFrame(&wire, in); err != nil {
		t.Fatal(err)
	}
	h, err := ReadHeader(&wire)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	stored, err := TeePayload(&out, &wire, h.Length, false, [4]byte{}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != "xxxx" {
		t.Fatalf("stored %q", stored)
	}
	if out.Len() != 200 {
		t.Fatalf("forwarded %d", out.Len())
	}
}

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

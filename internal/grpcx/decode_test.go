package grpcx

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestClassify(t *testing.T) {
	if Classify("application/grpc") != ClassGRPC {
		t.Fatal("application/grpc")
	}
	if Classify("application/grpc+proto; charset=utf-8") != ClassGRPC {
		t.Fatal("application/grpc+proto")
	}
	if Classify("application/grpc-web+proto") != ClassGRPCWeb {
		t.Fatal("grpc-web must be opaque")
	}
	if Classify("application/grpc-web") != ClassGRPCWeb {
		t.Fatal("application/grpc-web")
	}
	if Classify("application/grpc+json") != ClassNone {
		t.Fatal("grpc+json is not a trigger")
	}
	if Classify("text/plain") != ClassNone {
		t.Fatal("text/plain")
	}
}

func TestDecodeWellFormedStringAndVarint(t *testing.T) {
	msg := appendVarintField(nil, 2, 42)
	msg = appendBytesField(msg, 1, []byte("hello"))
	body := Frame(false, msg)
	got := Decode("application/grpc+proto", "", body)
	if got == nil || got.DecodeError != "" || got.Truncated {
		t.Fatalf("%+v", got)
	}
	if len(got.Messages) != 1 || got.Messages[0].Compressed || got.Messages[0].Length != len(msg) {
		t.Fatalf("msg %+v", got.Messages)
	}
	fields := got.Messages[0].Fields
	if len(fields) != 2 {
		t.Fatalf("fields %+v", fields)
	}
	if fields[0].Number != 2 || fields[0].WireType != 0 || fields[0].Uint != 42 {
		t.Fatalf("varint %+v", fields[0])
	}
	if fields[1].Number != 1 || fields[1].WireType != 2 || fields[1].Text != "hello" {
		t.Fatalf("string %+v", fields[1])
	}
}

func TestDecodeNestedMessage(t *testing.T) {
	inner := appendBytesField(nil, 1, []byte{0x00, 0x01, 0x02})
	msg := appendBytesField(nil, 3, inner)
	got := Decode("application/grpc", "", Frame(false, msg))
	if got.DecodeError != "" {
		t.Fatalf("err %s", got.DecodeError)
	}
	f := got.Messages[0].Fields[0]
	if f.Number != 3 || len(f.Nested) != 1 {
		t.Fatalf("nested %+v", f)
	}
	if f.Nested[0].Number != 1 || f.Nested[0].WireType != 2 || f.Nested[0].Text != "" {
		t.Fatalf("inner %+v", f.Nested[0])
	}
}

func TestDecodeMaxNestDepth(t *testing.T) {
	ok := appendVarintField(nil, 1, 1)
	for i := 0; i < model.GRPCMaxNestDepth-1; i++ {
		ok = appendBytesField(nil, 1, ok)
	}
	got := Decode("application/grpc", "", Frame(false, ok))
	if got.DecodeError != "" {
		t.Fatalf("depth %d should be ok: %+v", model.GRPCMaxNestDepth, got)
	}
	tooDeep := appendBytesField(nil, 1, ok)
	got = Decode("application/grpc", "", Frame(false, tooDeep))
	if got.DecodeError != model.GRPCDecodeMalformed {
		t.Fatalf("want malformed, got %+v", got)
	}
}

func TestDecodeMalformedFailOpen(t *testing.T) {
	body := []byte{0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xff}
	got := Decode("application/grpc", "", body)
	if got.DecodeError != model.GRPCDecodeMalformed {
		t.Fatalf("want malformed, got %+v", got)
	}
}

func TestDecodeTruncatedPrefix(t *testing.T) {
	got := Decode("application/grpc", "", []byte{0x00, 0x00})
	if got.DecodeError != model.GRPCDecodeTruncated || !got.Truncated {
		t.Fatalf("%+v", got)
	}
}

func TestDecodeTruncatedLength(t *testing.T) {
	body := []byte{0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x02}
	got := Decode("application/grpc", "", body)
	if got.DecodeError != model.GRPCDecodeTruncated {
		t.Fatalf("%+v", got)
	}
}

func TestDecodeCompressedFlagStoresRaw(t *testing.T) {
	body := Frame(true, []byte("raw-gzip-shaped"))
	got := Decode("application/grpc", "", body)
	if got.DecodeError != "" {
		t.Fatalf("%+v", got)
	}
	if len(got.Messages) != 1 || !got.Messages[0].Compressed || len(got.Messages[0].Fields) != 0 {
		t.Fatalf("compressed message %+v", got.Messages)
	}
}

func TestDecodeMessageEncodingGzipSkipped(t *testing.T) {
	got := Decode("application/grpc", "gzip", Frame(false, appendVarintField(nil, 1, 1)))
	if !got.Compressed || len(got.Messages) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestDecodeFlowGRPCWebOpaque(t *testing.T) {
	f := &model.Flow{
		Request: model.HTTPMessage{
			Headers: []model.Header{{Name: "Content-Type", Value: "application/grpc-web+proto"}},
			Body:    Frame(false, appendBytesField(nil, 1, []byte("hello"))),
		},
	}
	info, result := DecodeFlow(f)
	if info != nil || result != ResultSkipped {
		t.Fatalf("info=%+v result=%q", info, result)
	}
}

func TestDecodeFlowFlagOffNotCalled(t *testing.T) {
	// Classify still works; proxy is what gates the flag.
	if Classify("application/grpc") != ClassGRPC {
		t.Fatal("trigger")
	}
}

func TestDecodeFlowRequestAndResponse(t *testing.T) {
	req := Frame(false, appendBytesField(nil, 1, []byte("req")))
	resp := Frame(false, appendVarintField(nil, 2, 7))
	f := &model.Flow{
		Request: model.HTTPMessage{
			Headers: []model.Header{{Name: "content-type", Value: "application/grpc"}},
			Body:    req,
		},
		Response: model.HTTPMessage{
			Headers: []model.Header{{Name: "Content-Type", Value: "application/grpc+proto"}},
			Body:    resp,
		},
	}
	info, result := DecodeFlow(f)
	if result != ResultOK || info == nil || len(info.Messages) != 2 {
		t.Fatalf("info=%+v result=%q", info, result)
	}
	if info.Messages[0].Fields[0].Text != "req" {
		t.Fatalf("req %+v", info.Messages[0])
	}
	if info.Messages[1].Fields[0].Uint != 7 {
		t.Fatalf("resp %+v", info.Messages[1])
	}
}

func TestDecodeFlowTruncatedBody(t *testing.T) {
	f := &model.Flow{
		Request: model.HTTPMessage{
			Headers:   []model.Header{{Name: "Content-Type", Value: "application/grpc"}},
			Body:      Frame(false, appendVarintField(nil, 1, 1)),
			Truncated: true,
		},
	}
	info, result := DecodeFlow(f)
	if result != ResultTruncated || info == nil || info.DecodeError != model.GRPCDecodeTruncated {
		t.Fatalf("info=%+v result=%q", info, result)
	}
}

func appendVarintField(b []byte, num int, v uint64) []byte {
	b = appendVarint(b, uint64(num)<<3)
	return appendVarint(b, v)
}

func appendBytesField(b []byte, num int, payload []byte) []byte {
	b = appendVarint(b, uint64(num)<<3|2)
	b = appendVarint(b, uint64(len(payload)))
	return append(b, payload...)
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func TestFrameRoundTrip(t *testing.T) {
	msg := []byte{0x08, 0x01}
	got := Frame(false, msg)
	if got[0] != 0 || binary.BigEndian.Uint32(got[1:5]) != 2 || string(got[5:]) != string(msg) {
		t.Fatalf("%x", got)
	}
}

func TestDecodeFixed64And32(t *testing.T) {
	var msg []byte
	msg = appendVarint(msg, 1<<3|1)
	var u64 [8]byte
	binary.LittleEndian.PutUint64(u64[:], 99)
	msg = append(msg, u64[:]...)
	msg = appendVarint(msg, 2<<3|5)
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], 7)
	msg = append(msg, u32[:]...)
	got := Decode("application/grpc", "", Frame(false, msg))
	if len(got.Messages[0].Fields) != 2 {
		t.Fatalf("%+v", got.Messages[0].Fields)
	}
	if got.Messages[0].Fields[0].Uint != 99 || got.Messages[0].Fields[1].Uint != 7 {
		t.Fatalf("%+v", got.Messages[0].Fields)
	}
}

func TestDecodeEmptyBodyOK(t *testing.T) {
	got := Decode("application/grpc", "", nil)
	if got.DecodeError != "" || len(got.Messages) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestCompressedEncoding(t *testing.T) {
	if !CompressedEncoding("gzip") || !CompressedEncoding("Deflate") {
		t.Fatal("gzip/deflate")
	}
	if CompressedEncoding("identity") || CompressedEncoding("") {
		t.Fatal("identity")
	}
}

func TestMalformedDoesNotDumpParser(t *testing.T) {
	got := Decode("application/grpc", "", []byte{2, 0, 0, 0, 0})
	if got.DecodeError != model.GRPCDecodeMalformed {
		t.Fatalf("%+v", got)
	}
	if strings.Contains(got.DecodeError, " ") || strings.Contains(got.DecodeError, "offset") {
		t.Fatalf("DecodeError must be a bounded token: %q", got.DecodeError)
	}
}

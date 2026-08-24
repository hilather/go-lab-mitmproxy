package grpcx

import (
	"encoding/binary"
	"mime"
	"strings"
	"unicode/utf8"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

const (
	// Result tokens for labmitm_grpc_decode_total{result}. Empty means no-op.
	ResultOK        = "ok"
	ResultMalformed = "malformed"
	ResultTruncated = "truncated"
	ResultSkipped   = "skipped"
)

// Class is the content-type trigger (D66). grpc-web is opaque.
type Class int

const (
	ClassNone Class = iota
	ClassGRPC
	ClassGRPCWeb
)

// Classify returns whether content-type is application/grpc,
// application/grpc+proto, a grpc-web media type, or neither.
// Parameters (charset=…) are ignored. grpc-web is never a decode trigger.
func Classify(contentType string) Class {
	mt := mediaType(contentType)
	switch mt {
	case "application/grpc", "application/grpc+proto":
		return ClassGRPC
	}
	if strings.HasPrefix(mt, "application/grpc-web") {
		return ClassGRPCWeb
	}
	return ClassNone
}

// CompressedEncoding reports Message-Encoding / grpc-encoding gzip or deflate.
// The hop already stores the raw body; we do not add a decompressor.
func CompressedEncoding(v string) bool {
	enc := strings.ToLower(strings.TrimSpace(strings.Split(v, ";")[0]))
	return enc == "gzip" || enc == "deflate"
}

// Decode parses one captured gRPC body. contentType must already be ClassGRPC.
// encoding is grpc-encoding / Message-Encoding. Failure is fail-open: the
// returned GRPCInfo carries a bounded DecodeError; the hop still forwards.
func Decode(contentType, encoding string, body []byte) *model.GRPCInfo {
	info := &model.GRPCInfo{ContentType: mediaType(contentType)}
	if CompressedEncoding(encoding) {
		info.Compressed = true
		return info
	}
	msgs, errTok := parseFrames(body)
	info.Messages = msgs
	info.DecodeError = errTok
	if errTok == model.GRPCDecodeTruncated {
		info.Truncated = true
	}
	return info
}

// DecodeFlow attaches a best-effort tree from captured request/response
// bodies. grpc-web is skipped (content-type stays on HTTP headers). result
// is empty when the flow is not gRPC.
func DecodeFlow(f *model.Flow) (*model.GRPCInfo, string) {
	if f == nil {
		return nil, ""
	}
	reqCT := headerValue(f.Request.Headers, "content-type")
	respCT := headerValue(f.Response.Headers, "content-type")
	reqClass := Classify(reqCT)
	respClass := Classify(respCT)
	if reqClass != ClassGRPC && respClass != ClassGRPC {
		if reqClass == ClassGRPCWeb || respClass == ClassGRPCWeb {
			return nil, ResultSkipped
		}
		return nil, ""
	}

	var (
		msgs       []model.GRPCMessage
		decodeErr  string
		compressed bool
		ct         string
		truncated  bool
	)
	if reqClass == ClassGRPC {
		side := Decode(reqCT, encodingOf(f.Request.Headers), f.Request.Body)
		ct = side.ContentType
		compressed = compressed || side.Compressed
		truncated = truncated || side.Truncated || f.Request.Truncated
		msgs = append(msgs, side.Messages...)
		decodeErr = firstDecodeError(decodeErr, side.DecodeError)
		if f.Request.Truncated && decodeErr == "" {
			decodeErr = model.GRPCDecodeTruncated
			truncated = true
		}
	}
	if respClass == ClassGRPC {
		side := Decode(respCT, encodingOf(f.Response.Headers), f.Response.Body)
		if ct == "" {
			ct = side.ContentType
		}
		compressed = compressed || side.Compressed
		truncated = truncated || side.Truncated || f.Response.Truncated
		msgs = append(msgs, side.Messages...)
		decodeErr = firstDecodeError(decodeErr, side.DecodeError)
		if f.Response.Truncated && decodeErr == "" {
			decodeErr = model.GRPCDecodeTruncated
			truncated = true
		}
	}
	info := &model.GRPCInfo{
		ContentType: ct,
		Compressed:  compressed,
		Messages:    msgs,
		Truncated:   truncated,
		DecodeError: decodeErr,
	}
	return info, resultOf(info)
}

func resultOf(info *model.GRPCInfo) string {
	if info == nil {
		return ""
	}
	if info.Compressed && len(info.Messages) == 0 && info.DecodeError == "" {
		return ResultSkipped
	}
	switch info.DecodeError {
	case model.GRPCDecodeTruncated:
		return ResultTruncated
	case model.GRPCDecodeMalformed:
		return ResultMalformed
	default:
		return ResultOK
	}
}

func firstDecodeError(cur, next string) string {
	if cur == model.GRPCDecodeTruncated || next == model.GRPCDecodeTruncated {
		return model.GRPCDecodeTruncated
	}
	if cur != "" {
		return cur
	}
	return next
}

func encodingOf(headers []model.Header) string {
	if v := headerValue(headers, "grpc-encoding"); v != "" {
		return v
	}
	return headerValue(headers, "message-encoding")
}

func headerValue(headers []model.Header, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func mediaType(ct string) string {
	ct = strings.TrimSpace(ct)
	if ct == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		if i := strings.IndexByte(ct, ';'); i >= 0 {
			ct = ct[:i]
		}
		return strings.ToLower(strings.TrimSpace(ct))
	}
	return strings.ToLower(mt)
}

func parseFrames(body []byte) ([]model.GRPCMessage, string) {
	if len(body) == 0 {
		return nil, ""
	}
	var msgs []model.GRPCMessage
	off := 0
	for off < len(body) {
		if len(body)-off < 5 {
			return msgs, model.GRPCDecodeTruncated
		}
		flag := body[off]
		if flag > 1 {
			return msgs, model.GRPCDecodeMalformed
		}
		n := binary.BigEndian.Uint32(body[off+1 : off+5])
		off += 5
		if uint64(n) > uint64(len(body)-off) {
			return msgs, model.GRPCDecodeTruncated
		}
		payload := body[off : off+int(n)]
		off += int(n)
		msg := model.GRPCMessage{Compressed: flag == 1, Length: int(n)}
		if flag == 1 {
			msgs = append(msgs, msg)
			continue
		}
		fields, errTok := walkMessage(payload, 1)
		msg.Fields = fields
		msgs = append(msgs, msg)
		if errTok == errTooDeep {
			errTok = model.GRPCDecodeMalformed
		}
		if errTok != "" {
			return msgs, errTok
		}
	}
	return msgs, ""
}

// errTooDeep is converted to DecodeError=malformed at the length-prefix layer.
const errTooDeep = "too_deep"

func walkMessage(b []byte, depth int) ([]model.ProtoField, string) {
	if depth > model.GRPCMaxNestDepth {
		return nil, errTooDeep
	}
	var fields []model.ProtoField
	off := 0
	for off < len(b) {
		tag, n, ok := readVarint(b[off:])
		if !ok {
			return fields, model.GRPCDecodeMalformed
		}
		off += n
		num := int(tag >> 3)
		wt := int(tag & 7)
		if num == 0 {
			return fields, model.GRPCDecodeMalformed
		}
		f := model.ProtoField{Number: num, WireType: wt}
		switch wt {
		case 0:
			v, n, ok := readVarint(b[off:])
			if !ok {
				return fields, model.GRPCDecodeMalformed
			}
			off += n
			f.Uint = v
		case 1:
			if len(b)-off < 8 {
				return fields, model.GRPCDecodeMalformed
			}
			f.Uint = binary.LittleEndian.Uint64(b[off : off+8])
			off += 8
		case 2:
			ln, n, ok := readVarint(b[off:])
			if !ok {
				return fields, model.GRPCDecodeMalformed
			}
			off += n
			if ln > uint64(len(b)-off) {
				return fields, model.GRPCDecodeMalformed
			}
			payload := b[off : off+int(ln)]
			off += int(ln)
			nested, errTok := walkMessage(payload, depth+1)
			if errTok == errTooDeep {
				if isPrintableUTF8(payload) {
					f.Text = string(payload)
				}
				fields = append(fields, f)
				return fields, errTooDeep
			}
			switch {
			case errTok == "" && len(nested) > 0 && !isPrintableUTF8(payload):
				f.Nested = nested
			case isPrintableUTF8(payload):
				f.Text = string(payload)
			case errTok == "" && len(nested) > 0:
				f.Nested = nested
			}
		case 5:
			if len(b)-off < 4 {
				return fields, model.GRPCDecodeMalformed
			}
			f.Uint = uint64(binary.LittleEndian.Uint32(b[off : off+4]))
			off += 4
		default:
			return fields, model.GRPCDecodeMalformed
		}
		fields = append(fields, f)
	}
	return fields, ""
}

func readVarint(b []byte) (uint64, int, bool) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		x := b[i]
		v |= uint64(x&0x7f) << (7 * i)
		if x < 0x80 {
			if i == 9 && x > 1 {
				return 0, 0, false
			}
			return v, i + 1, true
		}
	}
	return 0, 0, false
}

func isPrintableUTF8(b []byte) bool {
	if len(b) == 0 || !utf8.Valid(b) {
		return false
	}
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
		if r == 0x7f {
			return false
		}
		i += size
	}
	return true
}

// Frame builds a gRPC length-prefix envelope (tests and capture fixtures).
func Frame(compressed bool, msg []byte) []byte {
	var hdr [5]byte
	if compressed {
		hdr[0] = 1
	}
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(msg)))
	out := make([]byte, 5+len(msg))
	copy(out, hdr[:])
	copy(out[5:], msg)
	return out
}

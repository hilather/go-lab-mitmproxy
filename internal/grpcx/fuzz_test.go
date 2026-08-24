package grpcx

import (
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func FuzzDecode(f *testing.F) {
	f.Add([]byte(nil), "application/grpc", "")
	f.Add(Frame(false, appendVarintField(nil, 1, 1)), "application/grpc+proto", "")
	f.Add(Frame(true, []byte("x")), "application/grpc", "gzip")
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0xff}, "application/grpc", "")
	f.Add([]byte{0xff}, "application/grpc-web+proto", "")
	f.Fuzz(func(t *testing.T, body []byte, ct, enc string) {
		if len(body) > 64*1024 {
			body = body[:64*1024]
		}
		_ = Decode(ct, enc, body)
		flow := &model.Flow{
			Request: model.HTTPMessage{
				Headers: []model.Header{{Name: "Content-Type", Value: ct}},
				Body:    body,
			},
		}
		_, _ = DecodeFlow(flow)
	})
}

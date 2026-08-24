package store

import "github.com/hilather/go-lab-mitmproxy/internal/model"

func cloneFlow(in *model.Flow) *model.Flow {
	if in == nil {
		return nil
	}
	out := *in
	out.Request = cloneMessage(in.Request)
	out.Response = cloneMessage(in.Response)
	out.TLS = cloneTLS(in.TLS)
	out.HTTP2 = cloneHTTP2(in.HTTP2)
	out.SOCKS = cloneSOCKS(in.SOCKS)
	out.WebSocket = cloneWebSocket(in.WebSocket)
	out.GRPC = cloneGRPC(in.GRPC)
	if in.RuleIDs != nil {
		out.RuleIDs = append([]string(nil), in.RuleIDs...)
	}
	return &out
}

func cloneMessage(in model.HTTPMessage) model.HTTPMessage {
	out := in
	out.Headers = cloneHeaders(in.Headers)
	out.Trailers = cloneHeaders(in.Trailers)
	if in.Body != nil {
		out.Body = append([]byte(nil), in.Body...)
	}
	return out
}

func cloneHTTP2(in *model.HTTP2Info) *model.HTTP2Info {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneSOCKS(in *model.SOCKSInfo) *model.SOCKSInfo {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneWebSocket(in *model.WebSocketInfo) *model.WebSocketInfo {
	if in == nil {
		return nil
	}
	out := *in
	if in.Frames != nil {
		out.Frames = make([]model.WebSocketFrame, len(in.Frames))
		for i := range in.Frames {
			out.Frames[i] = in.Frames[i]
			if in.Frames[i].Payload != nil {
				out.Frames[i].Payload = append([]byte(nil), in.Frames[i].Payload...)
			}
		}
	}
	return &out
}

func cloneGRPC(in *model.GRPCInfo) *model.GRPCInfo {
	if in == nil {
		return nil
	}
	out := *in
	if in.Messages != nil {
		out.Messages = make([]model.GRPCMessage, len(in.Messages))
		for i := range in.Messages {
			out.Messages[i] = in.Messages[i]
			out.Messages[i].Fields = cloneProtoFields(in.Messages[i].Fields)
		}
	}
	return &out
}

func cloneProtoFields(in []model.ProtoField) []model.ProtoField {
	if in == nil {
		return nil
	}
	out := make([]model.ProtoField, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Nested = cloneProtoFields(in[i].Nested)
	}
	return out
}

func cloneHeaders(in []model.Header) []model.Header {
	if in == nil {
		return nil
	}
	return append([]model.Header(nil), in...)
}

func cloneTLS(in *model.TLSInfo) *model.TLSInfo {
	if in == nil {
		return nil
	}
	out := *in
	if in.LeafDNS != nil {
		out.LeafDNS = append([]string(nil), in.LeafDNS...)
	}
	return &out
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	return append([]byte(nil), in...)
}

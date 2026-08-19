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
	if in.RuleIDs != nil {
		out.RuleIDs = append([]string(nil), in.RuleIDs...)
	}
	return &out
}

func cloneMessage(in model.HTTPMessage) model.HTTPMessage {
	out := in
	out.Headers = cloneHeaders(in.Headers)
	if in.Body != nil {
		out.Body = append([]byte(nil), in.Body...)
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

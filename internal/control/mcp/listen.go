package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
)

const resourceFlows = "labmitm://flows"

const metaProtocolVersion = "io.modelcontextprotocol/protocolVersion"

// enforceListenPin keeps subscriptions/listen on 2026-07-28 even when
// allowLegacyClients is true (D15). Header or _meta may carry the pin.
// On success the request body is restored so the official SDK can handle listen.
func (s *Server) enforceListenPin(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	headerVer := strings.TrimSpace(r.Header.Get(headerProtocolVersion))
	metaVer := ""
	if headerVer != ProtocolVersion {
		body, err := io.ReadAll(io.LimitReader(r.Body, s.maxBody+1))
		if err != nil {
			writeRPC(w, http.StatusBadRequest, domainerr.ValidationFailed("parse error"))
			return r, false
		}
		if int64(len(body)) > s.maxBody {
			writeRPC(w, http.StatusBadRequest, domainerr.ValidationFailed("request body too large"))
			return r, false
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		metaVer = listenMetaVersion(body)
	}
	if headerVer != ProtocolVersion && metaVer != ProtocolVersion {
		writeRPC(w, http.StatusBadRequest, domainerr.ValidationFailed("subscriptions/listen requires protocol "+ProtocolVersion))
		return r, false
	}
	// Official SDK requires the HTTP header once _meta carries a protocol
	// version. Promote a valid _meta pin so listen can proceed.
	if headerVer == "" && metaVer == ProtocolVersion {
		r.Header.Set(headerProtocolVersion, ProtocolVersion)
	}
	return r, true
}

func listenMetaVersion(body []byte) string {
	var req struct {
		Params struct {
			Meta map[string]any `json:"_meta"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	ver, _ := req.Params.Meta[metaProtocolVersion].(string)
	return strings.TrimSpace(ver)
}

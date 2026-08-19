package compat

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// Flow is the lab contract body for GET /compat/flows and GET /compat/flows/{id}.
// It is not a mitmproxy 11 drop-in.
type Flow struct {
	ID          string   `json:"id"`
	Intercepted bool     `json:"intercepted"`
	Type        string   `json:"type"`
	Error       *string  `json:"error"`
	Request     Request  `json:"request"`
	Response    *Message `json:"response"`
}

// Request is the mapped request side.
type Request struct {
	Method         string      `json:"method"`
	Scheme         string      `json:"scheme"`
	Host           string      `json:"host"`
	Port           int         `json:"port"`
	Path           string      `json:"path"`
	HTTPVersion    string      `json:"http_version"`
	Headers        [][]string  `json:"headers"`
	ContentLength  int         `json:"contentLength"`
	TimestampStart json.Number `json:"timestamp_start,omitempty"`
}

// Message is the mapped response side.
type Message struct {
	StatusCode    int         `json:"status_code"`
	Reason        string      `json:"reason"`
	HTTPVersion   string      `json:"http_version"`
	Headers       [][]string  `json:"headers"`
	ContentLength int         `json:"contentLength"`
	TimestampEnd  json.Number `json:"timestamp_end,omitempty"`
}

// MapFlow converts a captured flow to the lab compat JSON object.
func MapFlow(f *model.Flow) Flow {
	if f == nil {
		return Flow{Type: "http"}
	}
	scheme, host, port, path := splitURL(f)
	ver := httpVersion(f.Protocol)
	out := Flow{
		ID:          f.ID,
		Intercepted: f.Intercepted,
		Type:        flowType(f.Protocol),
		Request: Request{
			Method:        f.Method,
			Scheme:        scheme,
			Host:          host,
			Port:          port,
			Path:          path,
			HTTPVersion:   ver,
			Headers:       mapHeaders(f.Request.Headers),
			ContentLength: messageBytes(f.Request),
		},
	}
	if f.Error != "" {
		err := f.Error
		out.Error = &err
	}
	if !f.StartedAt.IsZero() {
		out.Request.TimestampStart = unixNumber(f.StartedAt)
	}
	if hasResponse(f) {
		out.Response = &Message{
			StatusCode:    f.Status,
			Reason:        http.StatusText(f.Status),
			HTTPVersion:   ver,
			Headers:       mapHeaders(f.Response.Headers),
			ContentLength: messageBytes(f.Response),
		}
		if !f.CompletedAt.IsZero() {
			out.Response.TimestampEnd = unixNumber(f.CompletedAt)
		}
	}
	return out
}

// MapList maps a newest-first page. Callers truncate to ListLimit.
func MapList(items []*model.Flow) []Flow {
	out := make([]Flow, 0, len(items))
	for _, f := range items {
		out = append(out, MapFlow(f))
	}
	return out
}

func hasResponse(f *model.Flow) bool {
	if f == nil {
		return false
	}
	if f.Status != 0 || f.Response.Size != 0 || len(f.Response.Body) > 0 || len(f.Response.Headers) > 0 {
		return true
	}
	return !f.CompletedAt.IsZero()
}

func flowType(proto string) string {
	switch proto {
	case model.FlowProtocolWebSocket:
		return "websocket"
	case model.FlowProtocolSOCKS5, model.FlowProtocolSOCKS4:
		return "socks"
	case model.FlowProtocolConnect:
		return "tcp"
	default:
		return "http"
	}
}

func httpVersion(proto string) string {
	if proto == model.FlowProtocolHTTP2 {
		return "HTTP/2.0"
	}
	return "HTTP/1.1"
}

func mapHeaders(in []model.Header) [][]string {
	out := make([][]string, 0, len(in))
	for _, h := range in {
		out = append(out, []string{h.Name, h.Value})
	}
	if out == nil {
		return [][]string{}
	}
	return out
}

func messageBytes(m model.HTTPMessage) int {
	if m.Size > 0 {
		return m.Size
	}
	return len(m.Body)
}

func unixNumber(t time.Time) json.Number {
	ms := t.UnixMilli()
	sec := ms / 1000
	frac := ms % 1000
	if frac == 0 {
		return json.Number(strconv.FormatInt(sec, 10))
	}
	return json.Number(strconv.FormatInt(sec, 10) + "." + pad3(frac))
}

func pad3(n int64) string {
	if n < 0 {
		n = -n
	}
	s := strconv.FormatInt(n, 10)
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}

func splitURL(f *model.Flow) (scheme, host string, port int, path string) {
	scheme = f.Scheme
	host = f.Host
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port, _ = strconv.Atoi(p)
	}
	path = "/"
	if u, err := url.Parse(f.URL); err == nil && f.URL != "" {
		if scheme == "" {
			scheme = u.Scheme
		}
		if host == "" {
			host = u.Hostname()
		}
		if port == 0 {
			if raw := u.Port(); raw != "" {
				port, _ = strconv.Atoi(raw)
			}
		}
		switch {
		case u.Opaque != "" && u.Scheme == "":
			path = u.Opaque
		default:
			p := u.EscapedPath()
			if p == "" {
				p = "/"
			}
			if u.RawQuery != "" {
				p += "?" + u.RawQuery
			}
			path = p
		}
	}
	if port == 0 {
		switch strings.ToLower(scheme) {
		case "https", "wss":
			port = 443
		case "http", "ws":
			port = 80
		}
	}
	return scheme, host, port, path
}

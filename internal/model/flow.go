package model

import (
	"net/url"
	"strings"
	"time"
)

const (
	FlowStateOpen      = "open"
	FlowStatePaused    = "paused"
	FlowStateCompleted = "completed"
	FlowStateDropped   = "dropped"
	FlowStateError     = "error"

	FlowProtocolHTTP11    = "http/1.1"
	FlowProtocolHTTP2     = "h2"
	FlowProtocolWebSocket = "websocket"
	FlowProtocolConnect   = "connect"
	FlowProtocolSOCKS5    = "socks5"
	FlowProtocolSOCKS4    = "socks4"

	SOCKSCmdConnect = "connect"
	SOCKSCmdBind    = "bind"
)

// Flow is one captured HTTP exchange (or CONNECT metadata).
type Flow struct {
	ID           string
	StartedAt    time.Time
	CompletedAt  time.Time
	State        string
	PausedPhase  string
	ClientAddr   string
	Method       string
	URL          string
	Host         string
	Scheme       string
	Protocol     string
	Status       int
	Error        string
	Intercepted  bool
	Request      HTTPMessage
	Response     HTTPMessage
	TLS          *TLSInfo
	HTTP2        *HTTP2Info
	SOCKS        *SOCKSInfo
	Via          string
	OriginalDest string
	Timings      Timings
	RuleIDs      []string
	Truncated    bool
}

// HTTPMessage is one side of a captured exchange.
type HTTPMessage struct {
	Headers   []Header
	Trailers  []Header
	Body      []byte
	Size      int
	Truncated bool
}

// HTTP2Info is captured HTTP/2 stream metadata.
type HTTP2Info struct {
	StreamID uint32
}

// SOCKSInfo is captured SOCKS CONNECT/BIND metadata.
type SOCKSInfo struct {
	Version int
	ATYP    string
	Dest    string
	Command string
	BND     string
}

// Header is an ordered, case-preserving HTTP header.
type Header struct {
	Name  string
	Value string
}

// TLSInfo is captured handshake metadata. It never includes key material.
type TLSInfo struct {
	SNI              string
	Version          string
	CipherSuite      string
	ALPN             string
	UpstreamVerified bool
	LeafDNS          []string
}

// CAStatus is exported on GET /v1/status and the UI. Never includes key material.
type CAStatus struct {
	Mode       string
	SPKISHA256 string
	Subject    string
	NotAfter   time.Time
}

// Timings is millisecond-resolution hop timing.
type Timings struct {
	DNSMs     int
	ConnectMs int
	TLSMs     int
	TTFBMs    int
	TotalMs   int
}

// InsertResult is the store acknowledgement for one accepted flow.
type InsertResult struct {
	ID         string
	Generation uint64
}

// FlowFilter selects store rows for List and Wait.
type FlowFilter struct {
	Host        string
	Method      string
	PathPrefix  string
	Status      int
	After       time.Time
	Intercepted *bool
	Scheme      string
	RuleID      string
	Protocol    string
	Via         string
}

// ListQuery is a filtered, cursor-paginated flow read.
type ListQuery struct {
	Filter FlowFilter
	Cursor string
	Limit  int
}

// ListResult is one page of flows, newest first.
type ListResult struct {
	Items      []*Flow
	NextCursor string
	Generation uint64
}

// StoreStats is a point-in-time occupancy snapshot.
type StoreStats struct {
	FlowCount  int
	Bytes      int64
	Generation uint64
	Epoch      uint64
	Evictions  uint64
}

// EvictTime is CompletedAt when set, otherwise StartedAt (open/paused).
func (f *Flow) EvictTime() time.Time {
	if f == nil {
		return time.Time{}
	}
	if !f.CompletedAt.IsZero() {
		return f.CompletedAt
	}
	return f.StartedAt
}

// Path is the decoded URL path (no query) used by list/wait filters.
func (f *Flow) Path() string {
	if f == nil {
		return ""
	}
	if f.URL == "" {
		return ""
	}
	u, err := url.Parse(f.URL)
	if err != nil {
		if i := strings.IndexAny(f.URL, "?#"); i >= 0 {
			return f.URL[:i]
		}
		return f.URL
	}
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

// ResidentBytes is request+response bodies plus a header budget.
// Spilled bodies (nil Body, Size set) still count.
func (f *Flow) ResidentBytes() int64 {
	if f == nil {
		return 0
	}
	return messageResident(f.Request) + messageResident(f.Response)
}

func messageResident(m HTTPMessage) int64 {
	n := int64(len(m.Body))
	if n == 0 {
		n = int64(m.Size)
	}
	for i := range m.Headers {
		n += int64(len(m.Headers[i].Name) + len(m.Headers[i].Value) + 4)
	}
	for i := range m.Trailers {
		n += int64(len(m.Trailers[i].Name) + len(m.Trailers[i].Value) + 4)
	}
	return n
}

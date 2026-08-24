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
	WSDirectionClient = "client"
	WSDirectionOrigin = "origin"

	WSMaxFrames     = 4096
	WSFrameOverhead = 64
	WSErrorProtocol = "websocket"
	SOCKSCmdUDP     = "udp"

	GRPCMaxNestDepth    = 8
	GRPCFieldOverhead   = 16
	GRPCDecodeTruncated = "truncated"
	GRPCDecodeMalformed = "malformed"
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
	WebSocket    *WebSocketInfo
	GRPC         *GRPCInfo
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
	StreamID       uint32
	ParentStreamID uint32
	PromisedID     uint32
	Pushed         bool
}

// SOCKSInfo is captured SOCKS CONNECT/BIND/UDP metadata.
type SOCKSInfo struct {
	Version int
	ATYP    string
	Dest    string
	Command string
	BND     string
	// User is the matching YAML userPass id after RFC 1929 success. Never the
	// username or password.
	User string
}

// WebSocketInfo is captured RFC 6455 frames when inspectFrames is on (D67).
type WebSocketInfo struct {
	FrameCount int
	Truncated  bool
	Frames     []WebSocketFrame
}

// WebSocketFrame is one captured frame. Payload is unmasked.
type WebSocketFrame struct {
	Direction string
	Opcode    string
	OpcodeNum int
	Fin       bool
	Masked    bool
	CloseCode int
	Payload   []byte
	Size      int
	Truncated bool
	Version   int
	ATYP      string
	Dest      string
	Command   string
	BND       string
	LastDest  string
	Datagrams int
}

// GRPCInfo is a best-effort gRPC length-prefix + protobuf wire tree (D66).
// DecodeError is a bounded token (truncated | malformed | "").
type GRPCInfo struct {
	ContentType string
	Compressed  bool
	Messages    []GRPCMessage
	Truncated   bool
	DecodeError string
}

// GRPCMessage is one length-prefixed gRPC message. Compressed messages
// keep Fields empty (no decompressor).
type GRPCMessage struct {
	Compressed bool
	Length     int
	Fields     []ProtoField
}

// ProtoField is one protobuf key. Bytes are not stored as hex (ResidentBytes
// would double-count); GET may hex-encode non-text at encode time.
type ProtoField struct {
	Number   int
	WireType int
	Text     string
	Uint     uint64
	Nested   []ProtoField
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

// ResidentBytes is request+response bodies plus a header budget
// plus captured WebSocket frames (64 bytes + payload each)
// plus the gRPC field tree (no parallel hex copy of the same bytes).
// Spilled bodies (nil Body, Size set) still count.
func (f *Flow) ResidentBytes() int64 {
	if f == nil {
		return 0
	}
	return messageResident(f.Request) + messageResident(f.Response) + websocketResident(f.WebSocket) + grpcResident(f.GRPC)
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

func websocketResident(ws *WebSocketInfo) int64 {
	if ws == nil {
		return 0
	}
	var n int64
	for i := range ws.Frames {
		n += WSFrameOverhead
		if l := int64(len(ws.Frames[i].Payload)); l > 0 {
			n += l
		} else {
			n += int64(ws.Frames[i].Size)
		}
	}
	return n
}

// TreeBytes is the gRPC field-tree resident size (no hex copy of the body).
func (g *GRPCInfo) TreeBytes() int64 {
	return grpcResident(g)
}

func grpcResident(g *GRPCInfo) int64 {
	if g == nil {
		return 0
	}
	n := int64(len(g.ContentType) + len(g.DecodeError))
	for i := range g.Messages {
		n += grpcMessageResident(&g.Messages[i])
	}
	return n
}

func grpcMessageResident(m *GRPCMessage) int64 {
	if m == nil {
		return 0
	}
	n := int64(GRPCFieldOverhead)
	for i := range m.Fields {
		n += protoFieldResident(&m.Fields[i])
	}
	return n
}

func protoFieldResident(f *ProtoField) int64 {
	if f == nil {
		return 0
	}
	n := int64(GRPCFieldOverhead) + int64(len(f.Text))
	for i := range f.Nested {
		n += protoFieldResident(&f.Nested[i])
	}
	return n
}

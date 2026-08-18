package model

import "time"

const (
	FlowStateOpen      = "open"
	FlowStatePaused    = "paused"
	FlowStateCompleted = "completed"
	FlowStateDropped   = "dropped"
	FlowStateError     = "error"

	FlowProtocolHTTP11    = "http/1.1"
	FlowProtocolWebSocket = "websocket"
	FlowProtocolConnect   = "connect"
)

// Flow is one captured HTTP exchange (or CONNECT metadata).
type Flow struct {
	ID          string
	StartedAt   time.Time
	CompletedAt time.Time
	State       string
	PausedPhase string
	ClientAddr  string
	Method      string
	URL         string
	Host        string
	Scheme      string
	Protocol    string
	Status      int
	Error       string
	Intercepted bool
	Request     HTTPMessage
	Response    HTTPMessage
	TLS         *TLSInfo
	Timings     Timings
	RuleIDs     []string
	Truncated   bool
}

// HTTPMessage is one side of a captured exchange.
type HTTPMessage struct {
	Headers   []Header
	Body      []byte
	Size      int
	Truncated bool
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

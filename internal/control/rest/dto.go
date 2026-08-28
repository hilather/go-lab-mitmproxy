package rest

import (
	"encoding/json"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/audit"
	"github.com/hilather/go-lab-mitmproxy/internal/buildinfo"
	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

type healthResponse struct {
	Status string `json:"status"`
}

type versionResponse struct {
	Version   string           `json:"version"`
	Commit    string           `json:"commit"`
	BuildTime string           `json:"buildTime"`
	Protocols versionProtocols `json:"protocols"`
}

type versionProtocols struct {
	ConfigAPI string `json:"configAPI"`
	REST      string `json:"rest"`
	MCP       string `json:"mcp"`
}

type capabilityViewResponse struct {
	Capabilities []capabilityInfo `json:"capabilities"`
}

type capabilityInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Mutating    bool   `json:"mutating"`
	Idempotent  bool   `json:"idempotent"`
}

type statusResponse struct {
	Ready     bool               `json:"ready"`
	Revisions json.RawMessage    `json:"revisions"`
	Listeners []listenerJSON     `json:"listeners"`
	Store     storeStatsJSON     `json:"store"`
	Intercept bool               `json:"intercept"`
	CA        caStatusJSON       `json:"ca"`
	Features  statusFeaturesJSON `json:"features"`
}

type statusFeaturesJSON struct {
	HTTP2                  bool `json:"http2"`
	HTTP2ClientCleartext   bool `json:"http2ClientCleartext"`
	HTTP2Origin            bool `json:"http2Origin"`
	HTTP2ExtendedConnect   bool `json:"http2ExtendedConnect"`
	HTTP2CapturePush       bool `json:"http2CapturePush"`
	HTTP2GRPCDecode        bool `json:"http2GRPCDecode"`
	InspectWebSocketFrames bool `json:"inspectWebSocketFrames"`
	SOCKS5                 bool `json:"socks5"`
	SOCKS4                 bool `json:"socks4"`
	AcceptBind             bool `json:"acceptBind"`
	AcceptUDPAssociate     bool `json:"acceptUDPAssociate"`
	AcceptUserPass         bool `json:"acceptUserPass"`
	OriginalDestination    bool `json:"originalDestination"`
	CompatFlowREST         bool `json:"compatFlowREST"`
}

type listenerJSON struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type storeStatsJSON struct {
	FlowCount  int    `json:"flowCount"`
	Bytes      int64  `json:"storeBytes"`
	Generation uint64 `json:"storeGeneration"`
	Epoch      uint64 `json:"epoch"`
}

type caStatusJSON struct {
	Mode       string `json:"mode,omitempty"`
	SPKISHA256 string `json:"spkiSha256,omitempty"`
	Subject    string `json:"subject,omitempty"`
	NotAfter   string `json:"notAfter,omitempty"`
}

type stateViewJSON struct {
	BootstrapRevision string          `json:"bootstrapRevision"`
	RuntimeRevision   string          `json:"runtimeRevision"`
	Generation        uint64          `json:"generation"`
	StoreGeneration   uint64          `json:"storeGeneration"`
	Drifted           bool            `json:"drifted"`
	LoadedAt          string          `json:"loadedAt,omitempty"`
	FlowCount         int             `json:"flowCount"`
	StoreBytes        int64           `json:"storeBytes"`
	Canonical         json.RawMessage `json:"canonical"`
}

type changeRequest struct {
	ExpectedRevision string            `json:"expectedRevision"`
	IdempotencyKey   string            `json:"idempotencyKey"`
	Reason           string            `json:"reason"`
	Force            bool              `json:"force"`
	Operations       []model.Operation `json:"operations"`
	State            json.RawMessage   `json:"state"`
}

type resetRequest struct {
	Reason string `json:"reason"`
}

type sessionCreateJSON struct {
	CSRF      string `json:"csrf"`
	ExpiresAt string `json:"expiresAt"`
}

type sessionViewJSON struct {
	ID        string   `json:"id"`
	Role      string   `json:"role"`
	Scopes    []string `json:"scopes"`
	CSRF      string   `json:"csrf,omitempty"`
	ExpiresAt string   `json:"expiresAt,omitempty"`
}

type deleteRequest struct {
	ExpectedStoreGeneration *uint64 `json:"expectedStoreGeneration"`
}

type waitRequest struct {
	Filter waitFilter `json:"filter"`
	// Timeout is coerced from a Go duration string (e.g. "10s") to ns.
	Timeout time.Duration `json:"timeout"`
}

type waitFilter struct {
	Host        string `json:"host"`
	Method      string `json:"method"`
	PathPrefix  string `json:"pathPrefix"`
	Status      *int   `json:"status"`
	After       string `json:"after"`
	Intercepted *bool  `json:"intercepted"`
	Protocol    string `json:"protocol"`
	Via         string `json:"via"`
}

type resumeRequest struct {
	Headers *[]model.Header `json:"headers"`
	Body    *string         `json:"body"`
}

type flowListJSON struct {
	Revision        string     `json:"revision"`
	StoreGeneration uint64     `json:"storeGeneration"`
	Items           []flowJSON `json:"items"`
	NextCursor      *string    `json:"nextCursor"`
}

type flowJSON struct {
	ID            string             `json:"id"`
	StartedAt     string             `json:"startedAt,omitempty"`
	CompletedAt   string             `json:"completedAt,omitempty"`
	State         string             `json:"state"`
	PausedPhase   string             `json:"pausedPhase,omitempty"`
	ClientAddr    string             `json:"clientAddr,omitempty"`
	Method        string             `json:"method"`
	URL           string             `json:"url"`
	Host          string             `json:"host"`
	Scheme        string             `json:"scheme"`
	Protocol      string             `json:"protocol"`
	Status        int                `json:"status"`
	Error         string             `json:"error,omitempty"`
	Intercepted   bool               `json:"intercepted"`
	Request       messageJSON        `json:"request"`
	Response      messageJSON        `json:"response"`
	TLS           *tlsInfoJSON       `json:"tls,omitempty"`
	HTTP2         *http2InfoJSON     `json:"http2,omitempty"`
	SOCKS         *socksInfoJSON     `json:"socks,omitempty"`
	WebSocket     *webSocketInfoJSON `json:"websocket,omitempty"`
	GRPC          *grpcInfoJSON      `json:"grpc,omitempty"`
	Via           string             `json:"via,omitempty"`
	OriginalDest  string             `json:"originalDest,omitempty"`
	Timings       timingsJSON        `json:"timings"`
	RuleIDs       []string           `json:"ruleIds,omitempty"`
	Truncated     bool               `json:"truncated"`
	RequestBytes  int                `json:"requestBytes"`
	ResponseBytes int                `json:"responseBytes"`
}

type messageJSON struct {
	Headers   []headerJSON `json:"headers,omitempty"`
	Trailers  []headerJSON `json:"trailers,omitempty"`
	Body      string       `json:"body,omitempty"`
	Size      int          `json:"size"`
	Truncated bool         `json:"truncated"`
}

type http2InfoJSON struct {
	StreamID       uint32 `json:"streamId"`
	ParentStreamID uint32 `json:"parentStreamId,omitempty"`
	PromisedID     uint32 `json:"promisedId,omitempty"`
	Pushed         bool   `json:"pushed,omitempty"`
}

type socksInfoJSON struct {
	Version int    `json:"version,omitempty"`
	ATYP    string `json:"atyp,omitempty"`
	Dest    string `json:"dest,omitempty"`
	Command string `json:"command,omitempty"`
	BND     string `json:"bnd,omitempty"`
	User    string `json:"user,omitempty"`
}

type webSocketInfoJSON struct {
	FrameCount int                  `json:"frameCount"`
	Truncated  bool                 `json:"truncated"`
	Frames     []webSocketFrameJSON `json:"frames,omitempty"`
}

type webSocketFrameJSON struct {
	Direction string `json:"direction"`
	Opcode    string `json:"opcode"`
	OpcodeNum int    `json:"opcodeNum"`
	Fin       bool   `json:"fin"`
	Masked    bool   `json:"masked"`
	CloseCode int    `json:"closeCode,omitempty"`
	Payload   string `json:"payload,omitempty"`
	Size      int    `json:"size"`
	Truncated bool   `json:"truncated"`
	Version   int    `json:"version,omitempty"`
	ATYP      string `json:"atyp,omitempty"`
	Dest      string `json:"dest,omitempty"`
	Command   string `json:"command,omitempty"`
	BND       string `json:"bnd,omitempty"`
	LastDest  string `json:"lastDest,omitempty"`
	Datagrams int    `json:"datagrams,omitempty"`
}

type grpcInfoJSON struct {
	ContentType string            `json:"contentType,omitempty"`
	Compressed  bool              `json:"compressed,omitempty"`
	Messages    []grpcMessageJSON `json:"messages,omitempty"`
	Truncated   bool              `json:"truncated"`
	DecodeError string            `json:"decodeError,omitempty"`
}

type grpcMessageJSON struct {
	Compressed bool             `json:"compressed"`
	Length     int              `json:"length"`
	Fields     []protoFieldJSON `json:"fields,omitempty"`
}

type protoFieldJSON struct {
	Number   int              `json:"number"`
	WireType int              `json:"wireType"`
	Text     string           `json:"text,omitempty"`
	Uint     uint64           `json:"uint,omitempty"`
	Nested   []protoFieldJSON `json:"nested,omitempty"`
}

type headerJSON struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type tlsInfoJSON struct {
	SNI              string   `json:"sni,omitempty"`
	Version          string   `json:"version,omitempty"`
	CipherSuite      string   `json:"cipherSuite,omitempty"`
	ALPN             string   `json:"alpn,omitempty"`
	UpstreamVerified bool     `json:"upstreamVerified"`
	LeafDNS          []string `json:"leafDns,omitempty"`
}

type timingsJSON struct {
	DNSMs     int `json:"dnsMs"`
	ConnectMs int `json:"connectMs"`
	TLSMs     int `json:"tlsMs"`
	TTFBMs    int `json:"ttfbMs"`
	TotalMs   int `json:"totalMs"`
}

type planJSON struct {
	PreviousRevision  string            `json:"previousRevision"`
	CandidateRevision string            `json:"candidateRevision"`
	RuntimeRevision   string            `json:"runtimeRevision,omitempty"`
	Generation        uint64            `json:"generation,omitempty"`
	Applied           bool              `json:"applied,omitempty"`
	Drifted           bool              `json:"drifted"`
	Diff              []app.DiffEntry   `json:"diff"`
	Warnings          []app.Warning     `json:"warnings,omitempty"`
	Operations        []model.Operation `json:"operations,omitempty"`
}

type exportJSON struct {
	Format            string          `json:"format"`
	Revision          string          `json:"revision"`
	BootstrapRevision string          `json:"bootstrapRevision"`
	Drifted           bool            `json:"drifted"`
	Body              json.RawMessage `json:"body"`
	HumanDiff         string          `json:"humanDiff,omitempty"`
}

type sseEventJSON struct {
	ID              string `json:"id,omitempty"`
	Host            string `json:"host,omitempty"`
	StoreGeneration uint64 `json:"storeGeneration"`
}

func fromVersion(info buildinfo.Info) versionResponse {
	return versionResponse{
		Version:   info.Version,
		Commit:    info.Commit,
		BuildTime: info.BuildTime,
		Protocols: versionProtocols{
			ConfigAPI: info.Protocols.ConfigAPI,
			REST:      info.Protocols.REST,
			MCP:       info.Protocols.MCP,
		},
	}
}

func fromCapabilities() capabilityViewResponse {
	src := capabilities.DiscoveryList()
	out := make([]capabilityInfo, 0, len(src))
	for _, d := range src {
		out = append(out, capabilityInfo{
			Name: d.Name, Version: d.Version, Description: d.Description,
			Mutating: d.Mutating, Idempotent: d.Idempotent,
		})
	}
	return capabilityViewResponse{Capabilities: out}
}

func fromPlan(p *app.Plan) planJSON {
	if p == nil {
		return planJSON{Diff: []app.DiffEntry{}}
	}
	return planJSON{
		PreviousRevision:  string(p.PreviousRevision),
		CandidateRevision: string(p.CandidateRevision),
		Drifted:           p.Drifted,
		Diff:              p.Diff,
		Warnings:          p.Warnings,
		Operations:        p.Operations,
	}
}

func fromApply(r *app.ApplyResult) planJSON {
	if r == nil {
		return planJSON{Diff: []app.DiffEntry{}}
	}
	out := fromPlan(&r.Plan)
	out.Applied = r.Applied
	out.Generation = uint64(r.Generation)
	out.RuntimeRevision = string(r.RuntimeRevision)
	return out
}

func fromCA(st model.CAStatus) caStatusJSON {
	return caStatusJSON{
		Mode:       st.Mode,
		SPKISHA256: st.SPKISHA256,
		Subject:    st.Subject,
		NotAfter:   rfc3339(st.NotAfter),
	}
}

func fromFlow(f *model.Flow, listItem bool) flowJSON {
	if f == nil {
		return flowJSON{}
	}
	out := flowJSON{
		ID:            f.ID,
		StartedAt:     rfc3339(f.StartedAt),
		CompletedAt:   rfc3339(f.CompletedAt),
		State:         f.State,
		PausedPhase:   f.PausedPhase,
		ClientAddr:    f.ClientAddr,
		Method:        f.Method,
		URL:           f.URL,
		Host:          f.Host,
		Scheme:        f.Scheme,
		Protocol:      f.Protocol,
		Status:        f.Status,
		Error:         f.Error,
		Intercepted:   f.Intercepted,
		Request:       fromMessage(f.Request, listItem),
		Response:      fromMessage(f.Response, listItem),
		Timings:       timingsJSON{DNSMs: f.Timings.DNSMs, ConnectMs: f.Timings.ConnectMs, TLSMs: f.Timings.TLSMs, TTFBMs: f.Timings.TTFBMs, TotalMs: f.Timings.TotalMs},
		RuleIDs:       append([]string(nil), f.RuleIDs...),
		Truncated:     f.Truncated,
		RequestBytes:  messageBytes(f.Request),
		ResponseBytes: messageBytes(f.Response),
	}
	out.Via = f.Via
	out.OriginalDest = f.OriginalDest
	if f.TLS != nil {
		out.TLS = &tlsInfoJSON{
			SNI: f.TLS.SNI, Version: f.TLS.Version, CipherSuite: f.TLS.CipherSuite,
			ALPN: f.TLS.ALPN, UpstreamVerified: f.TLS.UpstreamVerified, LeafDNS: append([]string(nil), f.TLS.LeafDNS...),
		}
	}
	if f.HTTP2 != nil {
		out.HTTP2 = fromHTTP2(f.HTTP2)
	}
	if f.SOCKS != nil {
		out.SOCKS = &socksInfoJSON{Version: f.SOCKS.Version, ATYP: f.SOCKS.ATYP, Dest: f.SOCKS.Dest, Command: f.SOCKS.Command, BND: f.SOCKS.BND, User: f.SOCKS.User}
	}
	out.WebSocket = fromWebSocket(f.WebSocket, listItem)
	out.GRPC = fromGRPC(f.GRPC, listItem)
	return out
}

func fromHTTP2(h *model.HTTP2Info) *http2InfoJSON {
	if h == nil {
		return nil
	}
	return &http2InfoJSON{
		StreamID:       h.StreamID,
		ParentStreamID: h.ParentStreamID,
		PromisedID:     h.PromisedID,
		Pushed:         h.Pushed,
	}
}

func fromWebSocket(ws *model.WebSocketInfo, listItem bool) *webSocketInfoJSON {
	if ws == nil {
		return nil
	}
	out := &webSocketInfoJSON{FrameCount: ws.FrameCount, Truncated: ws.Truncated}
	if listItem {
		return out
	}
	if len(ws.Frames) == 0 {
		return out
	}
	out.Frames = make([]webSocketFrameJSON, len(ws.Frames))
	for i, fr := range ws.Frames {
		size := fr.Size
		if size == 0 {
			size = len(fr.Payload)
		}
		out.Frames[i] = webSocketFrameJSON{
			Direction: fr.Direction,
			Opcode:    fr.Opcode,
			OpcodeNum: fr.OpcodeNum,
			Fin:       fr.Fin,
			Masked:    fr.Masked,
			CloseCode: fr.CloseCode,
			Payload:   string(fr.Payload),
			Size:      size,
			Truncated: fr.Truncated,
		}
	}
	return out
}

func fromGRPC(g *model.GRPCInfo, listItem bool) *grpcInfoJSON {
	if g == nil {
		return nil
	}
	out := &grpcInfoJSON{
		ContentType: g.ContentType,
		Compressed:  g.Compressed,
		Truncated:   g.Truncated,
		DecodeError: g.DecodeError,
	}
	if listItem {
		return out
	}
	if len(g.Messages) == 0 {
		return out
	}
	out.Messages = make([]grpcMessageJSON, len(g.Messages))
	for i, m := range g.Messages {
		out.Messages[i] = grpcMessageJSON{
			Compressed: m.Compressed,
			Length:     m.Length,
			Fields:     fromProtoFields(m.Fields),
		}
	}
	return out
}

func fromProtoFields(in []model.ProtoField) []protoFieldJSON {
	if len(in) == 0 {
		return nil
	}
	out := make([]protoFieldJSON, len(in))
	for i, f := range in {
		out[i] = protoFieldJSON{
			Number:   f.Number,
			WireType: f.WireType,
			Text:     f.Text,
			Uint:     f.Uint,
			Nested:   fromProtoFields(f.Nested),
		}
	}
	return out
}

func fromMessage(m model.HTTPMessage, listItem bool) messageJSON {
	out := messageJSON{
		Size:      messageBytes(m),
		Truncated: m.Truncated,
	}
	if listItem {
		return out
	}
	out.Headers = fromHeaders(m.Headers)
	out.Trailers = fromHeaders(m.Trailers)
	if len(m.Body) > 0 {
		out.Body = string(m.Body)
	}
	return out
}

func featuresFromSpec(st *app.Status, sp *model.Spec) statusFeaturesJSON {
	out := statusFeaturesJSON{}
	if st != nil {
		out.HTTP2 = st.Features.HTTP2
		out.SOCKS5 = st.Features.SOCKS5
		out.SOCKS4 = st.Features.SOCKS4
		out.OriginalDestination = st.Features.OriginalDestination
		out.CompatFlowREST = st.Features.CompatFlowREST
	}
	if sp != nil {
		out.HTTP2ClientCleartext = sp.Protocols.HTTP2.ClientCleartext
		out.HTTP2Origin = sp.Protocols.HTTP2.Origin
		out.HTTP2ExtendedConnect = sp.Protocols.HTTP2.ExtendedConnect
		out.HTTP2CapturePush = sp.Protocols.HTTP2.CapturePush
		out.HTTP2GRPCDecode = sp.Protocols.HTTP2.GRPCDecode
		out.InspectWebSocketFrames = sp.Protocols.WebSocket.InspectFrames
		out.AcceptBind = sp.Listeners.Proxy.AcceptBind
		out.AcceptUDPAssociate = sp.Listeners.Proxy.AcceptUDPAssociate
		out.AcceptUserPass = sp.Listeners.Proxy.AcceptUserPass
	}
	return out
}

func messageBytes(m model.HTTPMessage) int {
	if m.Size > 0 {
		return m.Size
	}
	return len(m.Body)
}

func fromHeaders(in []model.Header) []headerJSON {
	out := make([]headerJSON, 0, len(in))
	for _, h := range in {
		out = append(out, headerJSON{Name: h.Name, Value: h.Value})
	}
	return out
}

func fromAudit(ev audit.Event) audit.Event {
	return ev
}

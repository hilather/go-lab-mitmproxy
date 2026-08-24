package mcp

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/audit"
	"github.com/hilather/go-lab-mitmproxy/internal/buildinfo"
	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

type emptyIn struct{}

type idIn struct {
	ID string `json:"id"`
}

type exportIn struct {
	Format string `json:"format,omitempty"`
}

type changeIn struct {
	ExpectedRevision string            `json:"expectedRevision,omitempty"`
	IdempotencyKey   string            `json:"idempotencyKey,omitempty"`
	Reason           string            `json:"reason,omitempty"`
	Force            bool              `json:"force,omitempty"`
	Operations       []model.Operation `json:"operations,omitempty"`
}

type validateIn struct {
	State      json.RawMessage   `json:"state,omitempty"`
	Operations []model.Operation `json:"operations,omitempty"`
}

type resetIn struct {
	Reason string `json:"reason,omitempty"`
}

type deleteIn struct {
	ID                      string  `json:"id,omitempty"`
	ExpectedStoreGeneration *uint64 `json:"expectedStoreGeneration,omitempty"`
}

type clearIn struct {
	ExpectedStoreGeneration *uint64 `json:"expectedStoreGeneration,omitempty"`
}

type listIn struct {
	Host        string `json:"host,omitempty"`
	Method      string `json:"method,omitempty"`
	Status      *int   `json:"status,omitempty"`
	Scheme      string `json:"scheme,omitempty"`
	Intercepted *bool  `json:"intercepted,omitempty"`
	RuleID      string `json:"ruleId,omitempty"`
	PathPrefix  string `json:"pathPrefix,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Via         string `json:"via,omitempty"`
	Cursor      string `json:"cursor,omitempty"`
	Limit       int    `json:"limit,omitempty"`
}

type waitIn struct {
	Filter  waitFilter `json:"filter"`
	Timeout string     `json:"timeout,omitempty"`
}

type waitFilter struct {
	Host        string `json:"host,omitempty"`
	Method      string `json:"method,omitempty"`
	PathPrefix  string `json:"pathPrefix,omitempty"`
	Status      *int   `json:"status,omitempty"`
	After       string `json:"after,omitempty"`
	Intercepted *bool  `json:"intercepted,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Via         string `json:"via,omitempty"`
}

type resumeIn struct {
	ID      string          `json:"id"`
	Headers *[]model.Header `json:"headers,omitempty"`
	Body    *string         `json:"body,omitempty"`
}

type auditQueryIn struct {
	Limit int `json:"limit,omitempty"`
}

func (in changeIn) toChange() app.ChangeIn {
	return app.ChangeIn{
		ExpectedRevision: model.Revision(in.ExpectedRevision),
		IdempotencyKey:   in.IdempotencyKey,
		Reason:           in.Reason,
		Force:            in.Force,
		Operations:       in.Operations,
	}
}

func (in validateIn) toValidate() (app.ValidateIn, error) {
	st, err := decodeCandidateState(in.State)
	if err != nil {
		return app.ValidateIn{}, err
	}
	return app.ValidateIn{State: st, Operations: in.Operations}, nil
}

func decodeCandidateState(raw json.RawMessage) (*model.State, error) {
	raw = json.RawMessage(trimSpaceJSON(raw))
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	return config.DecodeJSON(raw)
}

func trimSpaceJSON(raw json.RawMessage) []byte {
	i, j := 0, len(raw)
	for i < j && (raw[i] == ' ' || raw[i] == '\n' || raw[i] == '\r' || raw[i] == '\t') {
		i++
	}
	for j > i && (raw[j-1] == ' ' || raw[j-1] == '\n' || raw[j-1] == '\r' || raw[j-1] == '\t') {
		j--
	}
	return raw[i:j]
}

func parseOptionalTime(raw, field string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, raw)
	}
	if err != nil {
		return time.Time{}, domainerr.ValidationFailed("invalid timestamp",
			domainerr.FieldViolation{Path: field, Code: "invalid_value", Message: field + " must be RFC3339"})
	}
	return t.UTC(), nil
}

func (in listIn) filter() (model.FlowFilter, error) {
	f := model.FlowFilter{
		Host:        in.Host,
		Method:      in.Method,
		Scheme:      in.Scheme,
		RuleID:      in.RuleID,
		PathPrefix:  in.PathPrefix,
		Protocol:    in.Protocol,
		Via:         in.Via,
		Intercepted: in.Intercepted,
	}
	if in.Status != nil {
		f.Status = *in.Status
	}
	return f, nil
}

func (in waitIn) toWait() (app.WaitIn, error) {
	f := model.FlowFilter{
		Host:        in.Filter.Host,
		Method:      in.Filter.Method,
		PathPrefix:  in.Filter.PathPrefix,
		Intercepted: in.Filter.Intercepted,
		Protocol:    in.Filter.Protocol,
		Via:         in.Filter.Via,
	}
	if in.Filter.Status != nil {
		f.Status = *in.Filter.Status
	}
	after, err := parseOptionalTime(in.Filter.After, "filter.after")
	if err != nil {
		return app.WaitIn{}, err
	}
	f.After = after
	var timeout time.Duration
	if in.Timeout != "" {
		d, err := time.ParseDuration(in.Timeout)
		if err != nil || d < 0 {
			return app.WaitIn{}, domainerr.ValidationFailed("invalid timeout",
				domainerr.FieldViolation{Path: "timeout", Code: "invalid_value", Message: "timeout must use Go duration syntax"})
		}
		timeout = d
	}
	return app.WaitIn{Filter: f, Timeout: timeout}, nil
}

func (in resumeIn) toPatch() *store.ResumePatch {
	if in.Headers == nil && in.Body == nil {
		return nil
	}
	p := store.ResumePatch{}
	if in.Headers != nil {
		p.Headers = *in.Headers
	}
	if in.Body != nil {
		p.Body = []byte(*in.Body)
	}
	return &p
}

type versionJSON struct {
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

type capabilityViewJSON struct {
	Capabilities []capabilityInfoJSON `json:"capabilities"`
}

type capabilityInfoJSON struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Mutating    bool   `json:"mutating"`
	Idempotent  bool   `json:"idempotent"`
}

type statusJSON struct {
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
	Format            string `json:"format"`
	Revision          string `json:"revision"`
	BootstrapRevision string `json:"bootstrapRevision"`
	Drifted           bool   `json:"drifted"`
	Body              string `json:"body"`
	HumanDiff         string `json:"humanDiff,omitempty"`
}

type flowListJSON struct {
	Revision        string     `json:"revision"`
	StoreGeneration uint64     `json:"storeGeneration"`
	Items           []flowJSON `json:"items"`
	NextCursor      *string    `json:"nextCursor"`
}

type flowJSON struct {
	ID            string         `json:"id"`
	StartedAt     string         `json:"startedAt,omitempty"`
	CompletedAt   string         `json:"completedAt,omitempty"`
	State         string         `json:"state"`
	PausedPhase   string         `json:"pausedPhase,omitempty"`
	ClientAddr    string         `json:"clientAddr,omitempty"`
	Method        string         `json:"method"`
	URL           string         `json:"url"`
	Host          string         `json:"host"`
	Scheme        string         `json:"scheme"`
	Protocol      string         `json:"protocol"`
	Status        int            `json:"status"`
	Error         string         `json:"error,omitempty"`
	Intercepted   bool           `json:"intercepted"`
	Request       messageJSON    `json:"request"`
	Response      messageJSON    `json:"response"`
	TLS           *tlsInfoJSON   `json:"tls,omitempty"`
	HTTP2         *http2InfoJSON `json:"http2,omitempty"`
	SOCKS         *socksInfoJSON `json:"socks,omitempty"`
	Via           string         `json:"via,omitempty"`
	OriginalDest  string         `json:"originalDest,omitempty"`
	Timings       timingsJSON    `json:"timings"`
	RuleIDs       []string       `json:"ruleIds,omitempty"`
	Truncated     bool           `json:"truncated"`
	RequestBytes  int            `json:"requestBytes"`
	ResponseBytes int            `json:"responseBytes"`
}

type messageJSON struct {
	Headers   []headerJSON `json:"headers,omitempty"`
	Trailers  []headerJSON `json:"trailers,omitempty"`
	Body      string       `json:"body,omitempty"`
	Size      int          `json:"size"`
	Truncated bool         `json:"truncated"`
}

type http2InfoJSON struct {
	StreamID uint32 `json:"streamId"`
}

type socksInfoJSON struct {
	Version int    `json:"version,omitempty"`
	ATYP    string `json:"atyp,omitempty"`
	Dest    string `json:"dest,omitempty"`
	Command string `json:"command,omitempty"`
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

type rawBodyJSON struct {
	ID          string `json:"id"`
	Side        string `json:"side"`
	ContentType string `json:"contentType"`
	Body        string `json:"body"`
	Size        int    `json:"size"`
	Truncated   bool   `json:"truncated"`
}

type caPEMJSON struct {
	PEM         string `json:"pem"`
	ContentType string `json:"contentType"`
}

type countJSON struct {
	Deleted int `json:"deleted,omitempty"`
}

type okJSON struct {
	OK bool `json:"ok"`
}

type auditListJSON struct {
	Events []audit.Event `json:"events"`
}

func fromVersion(info buildinfo.Info) versionJSON {
	return versionJSON{
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

func fromCapabilities() capabilityViewJSON {
	src := capabilities.DiscoveryList()
	out := make([]capabilityInfoJSON, 0, len(src))
	for _, d := range src {
		out = append(out, capabilityInfoJSON{
			Name: d.Name, Version: d.Version, Description: d.Description,
			Mutating: d.Mutating, Idempotent: d.Idempotent,
		})
	}
	return capabilityViewJSON{Capabilities: out}
}

func fromStatus(st *app.Status, view *app.StateView) (statusJSON, error) {
	if st == nil {
		return statusJSON{Listeners: []listenerJSON{}, Store: storeStatsJSON{}}, nil
	}
	rev, err := marshalAPI(st.Revisions)
	if err != nil {
		return statusJSON{}, err
	}
	out := statusJSON{
		Ready:     st.Ready,
		Revisions: rev,
		Listeners: []listenerJSON{},
		Store: storeStatsJSON{
			FlowCount:  st.Revisions.FlowCount,
			Bytes:      st.Revisions.StoreBytes,
			Generation: st.Revisions.StoreGeneration,
			Epoch:      st.Epoch,
		},
		Intercept: st.Intercept,
		CA:        fromCA(st.CA),
	}
	if view != nil && view.Canonical != nil {
		out.Listeners = []listenerJSON{
			{Name: "proxy", Address: view.Canonical.Spec.Listeners.Proxy.Address},
			{Name: "management", Address: view.Canonical.Spec.Listeners.Management.Address},
		}
		if view.Canonical.Spec.Listeners.OriginalDestination.Enabled {
			out.Listeners = append(out.Listeners, listenerJSON{
				Name:    "originalDestination",
				Address: view.Canonical.Spec.Listeners.OriginalDestination.Address,
			})
		}
		out.Features = featuresFromSpec(&view.Canonical.Spec)
	}
	return out, nil
}

func featuresFromSpec(sp *model.Spec) statusFeaturesJSON {
	if sp == nil {
		return statusFeaturesJSON{}
	}
	return statusFeaturesJSON{
		HTTP2:                  sp.Protocols.HTTP2.Enabled,
		HTTP2ClientCleartext:   sp.Protocols.HTTP2.ClientCleartext,
		HTTP2Origin:            sp.Protocols.HTTP2.Origin,
		HTTP2ExtendedConnect:   sp.Protocols.HTTP2.ExtendedConnect,
		HTTP2CapturePush:       sp.Protocols.HTTP2.CapturePush,
		HTTP2GRPCDecode:        sp.Protocols.HTTP2.GRPCDecode,
		InspectWebSocketFrames: sp.Protocols.WebSocket.InspectFrames,
		SOCKS5:                 sp.Listeners.Proxy.AcceptSOCKS5,
		SOCKS4:                 sp.Listeners.Proxy.AcceptSOCKS4,
		AcceptBind:             sp.Listeners.Proxy.AcceptBind,
		AcceptUDPAssociate:     sp.Listeners.Proxy.AcceptUDPAssociate,
		AcceptUserPass:         sp.Listeners.Proxy.AcceptUserPass,
		OriginalDestination:    sp.Listeners.OriginalDestination.Enabled,
		CompatFlowREST:         sp.Compat.FlowREST.Enabled,
	}
}

func fromCA(st model.CAStatus) caStatusJSON {
	return caStatusJSON{
		Mode:       st.Mode,
		SPKISHA256: st.SPKISHA256,
		Subject:    st.Subject,
		NotAfter:   rfc3339(st.NotAfter),
	}
}

func fromStateView(v *app.StateView) (stateViewJSON, error) {
	if v == nil {
		return stateViewJSON{}, nil
	}
	canon, err := marshalAPI(v.Canonical)
	if err != nil {
		return stateViewJSON{}, err
	}
	return stateViewJSON{
		BootstrapRevision: string(v.BootstrapRevision),
		RuntimeRevision:   string(v.RuntimeRevision),
		Generation:        uint64(v.Generation),
		StoreGeneration:   v.StoreGeneration,
		Drifted:           v.Drifted,
		LoadedAt:          rfc3339(v.LoadedAt),
		FlowCount:         v.FlowCount,
		StoreBytes:        v.StoreBytes,
		Canonical:         canon,
	}, nil
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

func fromExport(exp *app.Export) exportJSON {
	if exp == nil {
		return exportJSON{}
	}
	return exportJSON{
		Format:            string(exp.Format),
		Revision:          string(exp.Revision),
		BootstrapRevision: string(exp.BootstrapRevision),
		Drifted:           exp.Drifted,
		Body:              string(exp.Body),
		HumanDiff:         exp.HumanDiff,
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
		out.HTTP2 = &http2InfoJSON{StreamID: f.HTTP2.StreamID}
	}
	if f.SOCKS != nil {
		out.SOCKS = &socksInfoJSON{Version: f.SOCKS.Version, ATYP: f.SOCKS.ATYP, Dest: f.SOCKS.Dest, Command: f.SOCKS.Command}
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

func fromAuditList(list *app.AuditList) auditListJSON {
	events := []audit.Event{}
	if list != nil && list.Events != nil {
		events = list.Events
	}
	return auditListJSON{Events: events}
}

func rawSide(f *model.Flow, request bool) rawBodyJSON {
	side := f.Response
	name := "response"
	if request {
		side = f.Request
		name = "request"
	}
	ct := "application/octet-stream"
	for _, h := range side.Headers {
		if strings.EqualFold(h.Name, "Content-Type") && h.Value != "" {
			ct = h.Value
			break
		}
	}
	return rawBodyJSON{
		ID:          f.ID,
		Side:        name,
		ContentType: ct,
		Body:        string(side.Body),
		Size:        messageBytes(side),
		Truncated:   side.Truncated,
	}
}

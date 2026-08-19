package model

import "time"

const (
	FullPolicyReject      = "reject"
	FullPolicyEvictOldest = "evict_oldest"

	CAModeGenerate = "generate"
	CAModeFiles    = "files"

	MgmtAuthBearer            = "bearer"
	MgmtAuthDevLoopbackUnauth = "dev-loopback-unauth"

	RoleViewer        = "viewer"
	RoleOperator      = "operator"
	RoleAdministrator = "administrator"

	ScopeMITMRead      = "mitm.read"
	ScopeMITMWrite     = "mitm.write"
	ScopeMITMAdmin     = "mitm.admin"
	ScopeMITMAuditRead = "mitm.audit.read"

	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"

	RulePhaseRequest  = "request"
	RulePhaseResponse = "response"

	ActionBreakpoint = "breakpoint"
	ActionDrop       = "drop"
	ActionDelay      = "delay"
	ActionStatus     = "status"
	ActionHeader     = "header"
	ActionBody       = "body"
)

// ListenersSpec configures the proxy, management, and optional orig-dest listeners.
type ListenersSpec struct {
	Proxy               ProxyListenerSpec        `json:"proxy"`
	Management          MgmtListenerSpec         `json:"management"`
	OriginalDestination OriginalDestListenerSpec `json:"originalDestination"`
}

// ProxyListenerSpec is the data-plane listener.
type ProxyListenerSpec struct {
	Address      string `json:"address"`
	AcceptSOCKS5 bool   `json:"acceptSOCKS5"`
	AcceptSOCKS4 bool   `json:"acceptSOCKS4"`
}

// OriginalDestListenerSpec is the optional Linux REDIRECT listener.
// Empty Address materializes 127.0.0.1:8890 when Enabled.
type OriginalDestListenerSpec struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
}

// MgmtListenerSpec is the control-plane HTTP listener.
type MgmtListenerSpec struct {
	Address  string      `json:"address"`
	RESTPath string      `json:"restPath"`
	MCPPath  string      `json:"mcpPath"`
	TLS      ListenerTLS `json:"tls"`
}

// ListenerTLS is optional TLS for the management listener.
type ListenerTLS struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// ProxySpec is the forward-proxy posture (admission + target guards).
type ProxySpec struct {
	Hostname  string        `json:"hostname"`
	Admission AdmissionSpec `json:"admission"`
	Targets   TargetsSpec   `json:"targets"`
}

// AdmissionSpec caps concurrent proxy sessions and in-flight work.
type AdmissionSpec struct {
	MaxSessions          int           `json:"maxSessions"`
	MaxSessionsPerIP     int           `json:"maxSessionsPerIP"`
	MaxInFlight          int           `json:"maxInFlight"`
	MaxInFlightBytes     int64         `json:"maxInFlightBytes"`
	SessionTimeout       time.Duration `json:"sessionTimeout"`
	IdleTimeout          time.Duration `json:"idleTimeout"`
	HeaderTimeout        time.Duration `json:"headerTimeout"`
	DialTimeout          time.Duration `json:"dialTimeout"`
	UpstreamTimeout      time.Duration `json:"upstreamTimeout"`
	MaxConcurrentStreams int           `json:"maxConcurrentStreams"` // 0 materializes 100
}

// TargetsSpec is resolve-then-guard policy. Empty allowHosts means any name.
type TargetsSpec struct {
	DenyCloudMetadata bool     `json:"denyCloudMetadata"`
	DenyLinkLocal     bool     `json:"denyLinkLocal"`
	AllowLoopback     bool     `json:"allowLoopback"`
	AllowHosts        []string `json:"allowHosts"`
	DenyHosts         []string `json:"denyHosts"`
}

// TLSSpec is intercept policy. tls.upstream.verify is not an input field.
type TLSSpec struct {
	Intercept bool            `json:"intercept"`
	Hosts     []string        `json:"hosts"`
	Ports     []int           `json:"ports"`
	CA        CASpec          `json:"ca"`
	Upstream  TLSUpstreamSpec `json:"upstream"`
}

// CASpec is the in-process lab CA. mode generate is ephemeral; files loads PEM.
type CASpec struct {
	Mode     string `json:"mode"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// TLSUpstreamSpec is the only upstream TLS input. InsecureSkipVerify is the
// sole verify knob; a `verify` key is rejected as unknown.
type TLSUpstreamSpec struct {
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
	ExtraCAFiles       []string `json:"extraCAFiles"`
}

// RulesSpec is deterministic, default-off rewrite / breakpoint policy.
type RulesSpec struct {
	Enabled bool       `json:"enabled"`
	Items   []RuleSpec `json:"items"`
}

// RuleSpec is one first-match item. id must be unique and [a-z0-9-]{1,64}.
type RuleSpec struct {
	ID      string         `json:"id"`
	Enabled bool           `json:"enabled"`
	Phase   string         `json:"phase"`
	Match   RuleMatchSpec  `json:"match"`
	Action  RuleActionSpec `json:"action"`
}

// RuleMatchSpec fields are AND. Empty match matches everything.
type RuleMatchSpec struct {
	Host           string `json:"host"`
	PathPrefix     string `json:"pathPrefix"`
	PathExact      string `json:"pathExact"`
	Method         string `json:"method"`
	HeaderName     string `json:"headerName"`
	HeaderContains string `json:"headerContains"`
	Protocol       string `json:"protocol"`
}

// ProtocolsSpec is hop-protocol policy. HTTP/2 defaults off.
type ProtocolsSpec struct {
	HTTP2 HTTP2Spec `json:"http2"`
}

// HTTP2Spec enables inner+origin HTTP/2. Default off.
type HTTP2Spec struct {
	Enabled bool `json:"enabled"`
}

// CompatSpec is optional first-party compat adapters. Default off.
type CompatSpec struct {
	FlowREST FlowRESTCompatSpec `json:"flowREST"`
}

// FlowRESTCompatSpec is optional mitmproxy-inspired flow REST.
// Empty PathPrefix materializes /compat when Enabled.
type FlowRESTCompatSpec struct {
	Enabled    bool   `json:"enabled"`
	PathPrefix string `json:"pathPrefix"`
}

// RuleActionSpec is one deterministic action.
type RuleActionSpec struct {
	Type       string             `json:"type"`
	Delay      time.Duration      `json:"delay"`
	Status     int                `json:"status"`
	Headers    RuleHeadersSpec    `json:"headers"`
	Body       RuleBodySpec       `json:"body"`
	Breakpoint RuleBreakpointSpec `json:"breakpoint"`
}

// RuleHeadersSpec mutates headers for the header action.
type RuleHeadersSpec struct {
	Set    map[string]string `json:"set"`
	Remove []string          `json:"remove"`
}

// RuleBodySpec replaces a message body. Replace is capped at 64 KiB in YAML.
type RuleBodySpec struct {
	Replace string `json:"replace"`
}

// RuleBreakpointSpec pauses a session until resume, drop, or timeout.
type RuleBreakpointSpec struct {
	Timeout time.Duration `json:"timeout"`
}

// StoreSpec is the bounded in-memory flow inbox.
type StoreSpec struct {
	MaxFlows       int           `json:"maxFlows"`
	MaxBytes       int64         `json:"maxBytes"`
	MaxBodyBytes   int64         `json:"maxBodyBytes"`
	FullPolicy     string        `json:"fullPolicy"`
	MaxWait        time.Duration `json:"maxWait"`
	SpillDirectory string        `json:"spillDirectory"`
	SpillThreshold int64         `json:"spillThreshold"`
}

// UISpec toggles the embedded SPA. REST/MCP stay up when disabled.
type UISpec struct {
	Enabled bool `json:"enabled"`
}

// ManagementSpec is control-plane authentication and HTTP limits.
type ManagementSpec struct {
	Auth              MgmtAuthSpec `json:"auth"`
	MCP               MCPSpec      `json:"mcp"`
	OriginAllowlist   []string     `json:"originAllowlist"`
	BodyLimit         int64        `json:"bodyLimit"`
	RequestsPerSecond int          `json:"requestsPerSecond"`
	Burst             int          `json:"burst"`
	MaxConcurrent     int          `json:"maxConcurrent"`
}

// MgmtAuthSpec names an auth mode and optional tokens. There is no Basic.
type MgmtAuthSpec struct {
	Mode   string      `json:"mode"`
	Tokens []TokenSpec `json:"tokens"`
}

// TokenSpec is one lab static bearer principal. Secrets are file refs only.
type TokenSpec struct {
	ID         string   `json:"id"`
	SecretFile string   `json:"secretFile"`
	Role       string   `json:"role"`
	Scopes     []string `json:"scopes"`
}

// MCPSpec is MCP protocol knobs.
type MCPSpec struct {
	AllowLegacyClients bool `json:"allowLegacyClients"`
}

// ObservabilitySpec is process telemetry configuration.
type ObservabilitySpec struct {
	LogLevel string      `json:"logLevel"`
	Metrics  MetricsSpec `json:"metrics"`
	Audit    AuditSpec   `json:"audit"`
}

// MetricsSpec configures the OpenMetrics listener.
type MetricsSpec struct {
	Listen     string `json:"listen"`
	PublicPath bool   `json:"publicPath"`
}

// AuditSpec sizes the in-process audit ring.
type AuditSpec struct {
	Ring int `json:"ring"`
}

// KnownScope reports whether s is a v1alpha1 mitm scope.
func KnownScope(s string) bool {
	switch s {
	case ScopeMITMRead, ScopeMITMWrite, ScopeMITMAdmin, ScopeMITMAuditRead:
		return true
	default:
		return false
	}
}

// KnownRole reports whether r is a v1alpha1 token role.
func KnownRole(r string) bool {
	switch r {
	case RoleViewer, RoleOperator, RoleAdministrator:
		return true
	default:
		return false
	}
}

// KnownRulePhase reports whether p is request or response.
func KnownRulePhase(p string) bool {
	switch p {
	case RulePhaseRequest, RulePhaseResponse:
		return true
	default:
		return false
	}
}

// KnownRuleAction reports whether t is a v1alpha1 rule action.
func KnownRuleAction(t string) bool {
	switch t {
	case ActionBreakpoint, ActionDrop, ActionDelay, ActionStatus, ActionHeader, ActionBody:
		return true
	default:
		return false
	}
}

// KnownRuleProtocol reports whether p is a v1alpha1 match.protocol value.
func KnownRuleProtocol(p string) bool {
	switch p {
	case FlowProtocolHTTP11, FlowProtocolHTTP2, FlowProtocolWebSocket, FlowProtocolConnect, FlowProtocolSOCKS5, FlowProtocolSOCKS4:
		return true
	default:
		return false
	}
}

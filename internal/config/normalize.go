package config

import (
	"encoding/json"
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// Normalize returns a copy of st with nil slices materialized. Numeric and
// bool defaults are applied at decode time so explicit zeros stay visible.
func Normalize(st *model.State) (*model.State, error) {
	if st == nil {
		return nil, domainerr.ValidationFailed("nil state",
			domainerr.FieldViolation{Path: "", Code: violationRequired, Message: "state is nil"})
	}
	out, err := cloneState(st)
	if err != nil {
		return nil, err
	}
	materializeDefaults(&out.Spec)
	return out, nil
}

func cloneState(st *model.State) (*model.State, error) {
	b, err := json.Marshal(st)
	if err != nil {
		return nil, domainerr.Internal("clone marshal: " + err.Error())
	}
	var out model.State
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, domainerr.Internal("clone unmarshal: " + err.Error())
	}
	return &out, nil
}

func materializeDefaults(sp *model.Spec) {
	if strings.TrimSpace(sp.Listeners.Proxy.Address) == "" {
		sp.Listeners.Proxy.Address = DefaultProxyAddress
	}
	if strings.TrimSpace(sp.Listeners.Management.Address) == "" {
		sp.Listeners.Management.Address = DefaultMgmtAddress
	}
	if strings.TrimSpace(sp.Listeners.Management.RESTPath) == "" {
		sp.Listeners.Management.RESTPath = DefaultRESTPath
	}
	if strings.TrimSpace(sp.Listeners.Management.MCPPath) == "" {
		sp.Listeners.Management.MCPPath = DefaultMCPPath
	}
	if sp.Listeners.OriginalDestination.Enabled && strings.TrimSpace(sp.Listeners.OriginalDestination.Address) == "" {
		sp.Listeners.OriginalDestination.Address = DefaultOrigDestAddress
	}
	if sp.Compat.FlowREST.Enabled && strings.TrimSpace(sp.Compat.FlowREST.PathPrefix) == "" {
		sp.Compat.FlowREST.PathPrefix = DefaultCompatPathPrefix
	}
	if sp.Proxy.Admission.MaxConcurrentStreams == 0 {
		sp.Proxy.Admission.MaxConcurrentStreams = DefaultMaxConcurrentStreams
	}
	if strings.TrimSpace(sp.Proxy.Hostname) == "" {
		sp.Proxy.Hostname = DefaultProxyHostname
	}
	if sp.Proxy.Targets.AllowHosts == nil {
		sp.Proxy.Targets.AllowHosts = []string{}
	}
	if sp.Proxy.Targets.DenyHosts == nil {
		sp.Proxy.Targets.DenyHosts = []string{}
	}
	if strings.TrimSpace(sp.TLS.CA.Mode) == "" {
		sp.TLS.CA.Mode = model.CAModeGenerate
	}
	if sp.TLS.Hosts == nil {
		sp.TLS.Hosts = []string{}
	}
	if len(sp.TLS.Ports) == 0 {
		sp.TLS.Ports = []int{defaultTLSPort}
	}
	if sp.TLS.Upstream.ExtraCAFiles == nil {
		sp.TLS.Upstream.ExtraCAFiles = []string{}
	}
	if sp.Rules.Items == nil {
		sp.Rules.Items = []model.RuleSpec{}
	}
	for i := range sp.Rules.Items {
		if sp.Rules.Items[i].Action.Headers.Set == nil {
			sp.Rules.Items[i].Action.Headers.Set = map[string]string{}
		}
		if sp.Rules.Items[i].Action.Headers.Remove == nil {
			sp.Rules.Items[i].Action.Headers.Remove = []string{}
		}
	}
	if strings.TrimSpace(sp.Store.FullPolicy) == "" {
		sp.Store.FullPolicy = model.FullPolicyReject
	}
	if strings.TrimSpace(sp.Management.Auth.Mode) == "" {
		sp.Management.Auth.Mode = model.MgmtAuthBearer
	}
	if sp.Management.Auth.Tokens == nil {
		sp.Management.Auth.Tokens = []model.TokenSpec{}
	}
	for i := range sp.Management.Auth.Tokens {
		if sp.Management.Auth.Tokens[i].Scopes == nil {
			sp.Management.Auth.Tokens[i].Scopes = []string{}
		}
	}
	if sp.Management.OriginAllowlist == nil {
		sp.Management.OriginAllowlist = []string{}
	}
	if strings.TrimSpace(sp.Observability.LogLevel) == "" {
		sp.Observability.LogLevel = model.LogLevelInfo
	}
}

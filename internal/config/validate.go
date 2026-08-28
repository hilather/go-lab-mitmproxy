package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

var (
	ruleIDPattern           = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	compatPathPrefixPattern = regexp.MustCompile(`^/[-a-z0-9]+(/[-a-z0-9]+)*$`)
)

type validateOpts struct {
	// skipUserPassFiles omits usernameFile/passwordFile existence and RFC 1929
	// length checks. compiler.Compile sets this when Previous != nil so live
	// apply does not stat SOCKS secrets (D60).
	skipUserPassFiles bool
}

// Validate checks a (preferably normalized) state. It does not mutate st.
func Validate(st *model.State) error {
	return validateState(st, validateOpts{})
}

// ValidateLiveApply is Validate for live Compile (Previous set). It does not
// stat SOCKS username/password files so replaceRules cannot fail on a vanished
// file and cannot pick up new bytes without Reset (D60).
func ValidateLiveApply(st *model.State) error {
	return validateState(st, validateOpts{skipUserPassFiles: true})
}

func validateState(st *model.State, opts validateOpts) error {
	if st == nil {
		return domainerr.ValidationFailed("nil state",
			domainerr.FieldViolation{Path: "", Code: violationRequired, Message: "state is nil"})
	}
	var vs []domainerr.FieldViolation
	validateDocument(st, &vs)
	validateListeners(&st.Spec.Listeners, &vs, opts)
	validateCompat(&st.Spec, &vs)
	validateProtocols(&st.Spec.Protocols, &vs)
	validateProxy(&st.Spec.Proxy, &vs)
	validateTLS(&st.Spec.TLS, &vs)
	validateRules(&st.Spec.Rules, &vs)
	validateStore(&st.Spec.Store, &vs)
	validateManagement(&st.Spec.Management, &vs)
	validateObservability(&st.Spec.Observability, &vs)
	if len(vs) > 0 {
		return domainerr.ValidationFailed("Candidate state is invalid.", vs...)
	}
	return nil
}

func validateDocument(st *model.State, vs *[]domainerr.FieldViolation) {
	if st.APIVersion != model.APIVersionV1Alpha1 {
		code := violationUnsupportedVersion
		msg := fmt.Sprintf("apiVersion must be %q", model.APIVersionV1Alpha1)
		if strings.TrimSpace(st.APIVersion) == "" {
			code = violationRequired
			msg = "apiVersion is required"
		}
		*vs = append(*vs, domainerr.FieldViolation{Path: "apiVersion", Code: code, Message: msg})
	}
	if st.Kind != model.KindLabMITM {
		code := violationInvalidValue
		msg := fmt.Sprintf("kind must be %q", model.KindLabMITM)
		if strings.TrimSpace(st.Kind) == "" {
			code = violationRequired
			msg = "kind is required"
		}
		*vs = append(*vs, domainerr.FieldViolation{Path: "kind", Code: code, Message: msg})
	}
	if strings.TrimSpace(st.Metadata.Name) == "" {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "metadata.name",
			Code:    violationRequired,
			Message: "metadata.name is required",
		})
	}
}

func validateListeners(l *model.ListenersSpec, vs *[]domainerr.FieldViolation, opts validateOpts) {
	validateTCPAddr("spec.listeners.proxy.address", l.Proxy.Address, vs)
	validateTCPAddr("spec.listeners.management.address", l.Management.Address, vs)
	if l.Management.RESTPath != "" && !strings.HasPrefix(l.Management.RESTPath, "/") {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.management.restPath",
			Code:    violationInvalidValue,
			Message: "restPath must start with /",
		})
	}
	if l.Management.MCPPath != "" && !strings.HasPrefix(l.Management.MCPPath, "/") {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.management.mcpPath",
			Code:    violationInvalidValue,
			Message: "mcpPath must start with /",
		})
	}
	validateFilePair("spec.listeners.management.tls", l.Management.TLS.Enabled, l.Management.TLS.CertFile, l.Management.TLS.KeyFile, vs)
	if l.OriginalDestination.Enabled {
		validateTCPAddr("spec.listeners.originalDestination.address", l.OriginalDestination.Address, vs)
	}
	validateProxyListener(&l.Proxy, vs, opts)
}

func validateProxyListener(p *model.ProxyListenerSpec, vs *[]domainerr.FieldViolation, opts validateOpts) {
	if p.AcceptBind && !p.AcceptSOCKS5 && !p.AcceptSOCKS4 {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.proxy.acceptBind",
			Code:    violationInvalidValue,
			Message: "acceptBind requires acceptSOCKS5 or acceptSOCKS4",
		})
	}
	if p.AcceptUDPAssociate && !p.AcceptSOCKS5 {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.proxy.acceptUDPAssociate",
			Code:    violationInvalidValue,
			Message: "acceptUDPAssociate requires acceptSOCKS5",
		})
	}
	if p.AcceptUserPass {
		if !p.AcceptSOCKS5 {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    "spec.listeners.proxy.acceptUserPass",
				Code:    violationInvalidValue,
				Message: "acceptUserPass requires acceptSOCKS5",
			})
		}
		if len(p.UserPass.Users) == 0 {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    "spec.listeners.proxy.acceptUserPass",
				Code:    violationInvalidValue,
				Message: "acceptUserPass requires at least one user",
			})
		}
	}
	validateUserPassUsers(p.UserPass.Users, vs, opts.skipUserPassFiles)
}

func validateUserPassUsers(users []model.UserPassUserSpec, vs *[]domainerr.FieldViolation, skipFiles bool) {
	ids := map[string]string{}
	for i, u := range users {
		path := indexPath("spec.listeners.proxy.userPass.users", i)
		id := strings.TrimSpace(u.ID)
		if id == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: path + ".id", Code: violationEmptyID, Message: "user id is required"})
		} else if !ruleIDPattern.MatchString(id) {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".id",
				Code:    violationInvalidValue,
				Message: "user id must match [a-z0-9-]{1,64}",
			})
		} else if prev, ok := ids[id]; ok {
			*vs = append(*vs, domainerr.FieldViolation{Path: path + ".id", Code: violationDuplicateID, Message: "duplicate user id (first at " + prev + ")"})
		} else {
			ids[id] = path + ".id"
		}
		if strings.TrimSpace(u.UsernameFile) == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: path + ".usernameFile", Code: violationRequired, Message: "usernameFile is required"})
		} else if !skipFiles {
			requireExistingFile(path+".usernameFile", u.UsernameFile, vs)
			checkRFC1929FileLength(path+".usernameFile", u.UsernameFile, "username", vs)
		}
		if strings.TrimSpace(u.PasswordFile) == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: path + ".passwordFile", Code: violationRequired, Message: "passwordFile is required"})
		} else if !skipFiles {
			requireExistingFile(path+".passwordFile", u.PasswordFile, vs)
			checkRFC1929FileLength(path+".passwordFile", u.PasswordFile, "password", vs)
		}
	}
}

func validateProtocols(p *model.ProtocolsSpec, vs *[]domainerr.FieldViolation) {
	h := p.HTTP2
	if h.Origin && !h.Enabled {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.protocols.http2.origin",
			Code:    violationInvalidValue,
			Message: "origin requires protocols.http2.enabled",
		})
	}
	if h.ExtendedConnect && !h.Enabled && !h.ClientCleartext {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.protocols.http2.extendedConnect",
			Code:    violationInvalidValue,
			Message: "extendedConnect requires protocols.http2.enabled or clientCleartext",
		})
	}
	if h.CapturePush && !h.Origin {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.protocols.http2.capturePush",
			Code:    violationInvalidValue,
			Message: "capturePush requires protocols.http2.origin",
		})
	}
	if h.GRPCDecode && !h.Enabled && !h.Origin {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.protocols.http2.grpcDecode",
			Code:    violationInvalidValue,
			Message: "grpcDecode requires protocols.http2.enabled or origin",
		})
	}
}

func validateCompat(sp *model.Spec, vs *[]domainerr.FieldViolation) {
	prefix := strings.TrimSpace(sp.Compat.FlowREST.PathPrefix)
	if prefix == "" && !sp.Compat.FlowREST.Enabled {
		return
	}
	if prefix == "" {
		prefix = DefaultCompatPathPrefix
	}
	if !compatPathPrefixPattern.MatchString(prefix) {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.compat.flowREST.pathPrefix",
			Code:    violationInvalidValue,
			Message: "pathPrefix must match /^/[-a-z0-9]+(/[-a-z0-9]+)*$/",
		})
		return
	}
	restPath := strings.TrimSpace(sp.Listeners.Management.RESTPath)
	if restPath == "" {
		restPath = DefaultRESTPath
	}
	mcpPath := strings.TrimSpace(sp.Listeners.Management.MCPPath)
	if mcpPath == "" {
		mcpPath = DefaultMCPPath
	}
	for _, blocked := range []string{"/", "/healthz", "/config", "/.well-known", restPath, mcpPath} {
		if pathsCollide(prefix, blocked) {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    "spec.compat.flowREST.pathPrefix",
				Code:    violationInvalidValue,
				Message: "pathPrefix must not collide with restPath, mcpPath, or reserved management paths",
			})
			return
		}
	}
}

func pathsCollide(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	// "/" prefixes every path; only an exact match (above) is a collision.
	if a == "/" || b == "/" {
		return false
	}
	return strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}

func validateTCPAddr(path, addr string, vs *[]domainerr.FieldViolation) {
	validateHostPort(path, addr, false, vs)
}

func validateHostPort(path, addr string, allowEmpty bool, vs *[]domainerr.FieldViolation) {
	if strings.TrimSpace(addr) == "" {
		if !allowEmpty {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path,
				Code:    violationRequired,
				Message: "listen address is required",
			})
		}
		return
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    path,
			Code:    violationInvalidValue,
			Message: "listen address must parse as host:port",
		})
		return
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    path,
			Code:    violationInvalidValue,
			Message: "listen address port must be 1–65535",
		})
	}
}

func validateProxy(p *model.ProxySpec, vs *[]domainerr.FieldViolation) {
	if strings.TrimSpace(p.Hostname) == "" {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.proxy.hostname",
			Code:    violationRequired,
			Message: "proxy.hostname is required",
		})
	}
	validateAdmission(&p.Admission, vs)
	for i, h := range p.Targets.AllowHosts {
		if strings.TrimSpace(h) == "" {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    indexPath("spec.proxy.targets.allowHosts", i),
				Code:    violationInvalidValue,
				Message: "allowHosts entries must be non-empty",
			})
		}
	}
	for i, h := range p.Targets.DenyHosts {
		if strings.TrimSpace(h) == "" {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    indexPath("spec.proxy.targets.denyHosts", i),
				Code:    violationInvalidValue,
				Message: "denyHosts entries must be non-empty",
			})
		}
	}
}

func validateAdmission(a *model.AdmissionSpec, vs *[]domainerr.FieldViolation) {
	if a.MaxSessions <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.proxy.admission.maxSessions", Code: violationInvalidValue, Message: "maxSessions must be > 0"})
	}
	if a.MaxSessionsPerIP <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.proxy.admission.maxSessionsPerIP", Code: violationInvalidValue, Message: "maxSessionsPerIP must be > 0"})
	}
	if a.MaxInFlight <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.proxy.admission.maxInFlight", Code: violationInvalidValue, Message: "maxInFlight must be > 0"})
	}
	if a.MaxInFlightBytes <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.proxy.admission.maxInFlightBytes", Code: violationInvalidValue, Message: "maxInFlightBytes must be > 0"})
	}
	if a.SessionTimeout <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.proxy.admission.sessionTimeout", Code: violationInvalidValue, Message: "sessionTimeout must be > 0"})
	}
	if a.IdleTimeout <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.proxy.admission.idleTimeout", Code: violationInvalidValue, Message: "idleTimeout must be > 0"})
	}
	if a.HeaderTimeout <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.proxy.admission.headerTimeout", Code: violationInvalidValue, Message: "headerTimeout must be > 0"})
	}
	if a.DialTimeout <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.proxy.admission.dialTimeout", Code: violationInvalidValue, Message: "dialTimeout must be > 0"})
	}
	if a.UpstreamTimeout <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.proxy.admission.upstreamTimeout", Code: violationInvalidValue, Message: "upstreamTimeout must be > 0"})
	}
	if a.MaxConcurrentStreams <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.proxy.admission.maxConcurrentStreams", Code: violationInvalidValue, Message: "maxConcurrentStreams must be > 0"})
	}
}

func validateTLS(t *model.TLSSpec, vs *[]domainerr.FieldViolation) {
	switch t.CA.Mode {
	case "", model.CAModeGenerate:
		if strings.TrimSpace(t.CA.CertFile) != "" || strings.TrimSpace(t.CA.KeyFile) != "" {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    "spec.tls.ca",
				Code:    violationInvalidValue,
				Message: "ca certFile/keyFile are illegal when mode is generate",
			})
		}
	case model.CAModeFiles:
		if strings.TrimSpace(t.CA.CertFile) == "" || strings.TrimSpace(t.CA.KeyFile) == "" {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    "spec.tls.ca",
				Code:    violationRequired,
				Message: "mode files requires certFile and keyFile",
			})
		} else {
			requireExistingFile("spec.tls.ca.certFile", t.CA.CertFile, vs)
			validateCAKeyFile("spec.tls.ca.keyFile", t.CA.KeyFile, vs)
		}
	default:
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.tls.ca.mode",
			Code:    violationInvalidValue,
			Message: "tls.ca.mode must be generate or files",
		})
	}
	for i, p := range t.Ports {
		if p < 1 || p > 65535 {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    indexPath("spec.tls.ports", i),
				Code:    violationInvalidValue,
				Message: "tls.ports entries must be 1–65535",
			})
		}
	}
	for i, f := range t.Upstream.ExtraCAFiles {
		if strings.TrimSpace(f) == "" {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    indexPath("spec.tls.upstream.extraCAFiles", i),
				Code:    violationInvalidValue,
				Message: "extraCAFiles entries must be non-empty",
			})
			continue
		}
		requireExistingFile(indexPath("spec.tls.upstream.extraCAFiles", i), f, vs)
	}
}

func validateRules(r *model.RulesSpec, vs *[]domainerr.FieldViolation) {
	ids := map[string]string{}
	for i, item := range r.Items {
		path := indexPath("spec.rules.items", i)
		id := strings.TrimSpace(item.ID)
		if id == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: path + ".id", Code: violationEmptyID, Message: "rule id is required"})
		} else if !ruleIDPattern.MatchString(id) {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".id",
				Code:    violationInvalidValue,
				Message: "rule id must match [a-z0-9-]{1,64}",
			})
		} else if prev, ok := ids[id]; ok {
			*vs = append(*vs, domainerr.FieldViolation{Path: path + ".id", Code: violationDuplicateID, Message: "duplicate rule id (first at " + prev + ")"})
		} else {
			ids[id] = path + ".id"
		}
		if strings.TrimSpace(item.Phase) == "" {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".phase",
				Code:    violationRequired,
				Message: "phase is required",
			})
		} else if !model.KnownRulePhase(item.Phase) {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".phase",
				Code:    violationInvalidValue,
				Message: "phase must be request, response, or websocket",
			})
		}
		if strings.TrimSpace(item.Action.Type) == "" {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".action.type",
				Code:    violationRequired,
				Message: "action.type is required",
			})
		} else if !model.KnownRuleAction(item.Action.Type) {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".action.type",
				Code:    violationInvalidValue,
				Message: "action.type must be breakpoint, drop, delay, status, header, body, silent, hang, redirect, or block",
			})
		}
		validateRulePhaseAction(path, item, vs)
		if item.Action.Delay < 0 || item.Action.Delay > MaxRuleDelay {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".action.delay",
				Code:    violationInvalidValue,
				Message: "action.delay must be between 0 and 30s",
			})
		}
		if item.Action.Status != 0 && (item.Action.Status < 400 || item.Action.Status > 599) {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".action.status",
				Code:    violationInvalidValue,
				Message: "action.status must be empty or 400–599",
			})
		}
		if int64(len(item.Action.Body.Replace)) > MaxRuleBodyReplace {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".action.body.replace",
				Code:    violationInvalidValue,
				Message: "action.body.replace must be ≤ 64KiB",
			})
		}
		if proto := strings.TrimSpace(item.Match.Protocol); proto != "" && !model.KnownRuleProtocol(proto) {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".match.protocol",
				Code:    violationInvalidValue,
				Message: "match.protocol must be http/1.1, h2, websocket, connect, socks5, or socks4",
			})
		}
		if item.Action.Type == model.ActionBreakpoint {
			if item.Action.Breakpoint.Timeout < time.Second || item.Action.Breakpoint.Timeout > MaxBreakpointTimeout {
				*vs = append(*vs, domainerr.FieldViolation{
					Path:    path + ".action.breakpoint.timeout",
					Code:    violationInvalidValue,
					Message: "breakpoint.timeout must be between 1s and 60s",
				})
			}
		}
		if close := strings.TrimSpace(item.Action.Silent.Close); close != "" && close != model.SilentCloseRST && close != model.SilentCloseFIN {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".action.silent.close",
				Code:    violationInvalidValue,
				Message: "silent.close must be rst or fin",
			})
		}
		if close := strings.TrimSpace(item.Action.Hang.Close); close != "" && close != model.SilentCloseRST && close != model.SilentCloseFIN {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".action.hang.close",
				Code:    violationInvalidValue,
				Message: "hang.close must be rst or fin",
			})
		}
		if item.Action.Type == model.ActionHang {
			if item.Action.Hang.Timeout < MinHangTimeout || item.Action.Hang.Timeout > MaxHangTimeout {
				code := violationInvalidValue
				msg := "hang.timeout must be between 1s and 30s"
				if item.Action.Hang.Timeout == 0 {
					code = violationRequired
					msg = "hang.timeout is required"
				}
				*vs = append(*vs, domainerr.FieldViolation{
					Path:    path + ".action.hang.timeout",
					Code:    code,
					Message: msg,
				})
			}
		}
		if item.Action.Type == model.ActionRedirect {
			loc := strings.TrimSpace(item.Action.Redirect.Location)
			if loc == "" {
				*vs = append(*vs, domainerr.FieldViolation{
					Path:    path + ".action.redirect.location",
					Code:    violationRequired,
					Message: "redirect.location is required",
				})
			} else if len(loc) > MaxRedirectLocation || strings.ContainsAny(loc, "\r\n\x00") {
				*vs = append(*vs, domainerr.FieldViolation{
					Path:    path + ".action.redirect.location",
					Code:    violationInvalidValue,
					Message: "redirect.location must be ≤ 2048 bytes and must not contain CR, LF, or NUL",
				})
			}
			if st := item.Action.Redirect.Status; st != 0 && !knownRedirectStatus(st) {
				*vs = append(*vs, domainerr.FieldViolation{
					Path:    path + ".action.redirect.status",
					Code:    violationInvalidValue,
					Message: "redirect.status must be 301, 302, 303, 307, or 308",
				})
			}
		}
	}
}

func knownRedirectStatus(st int) bool {
	switch st {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

func validateRulePhaseAction(path string, item model.RuleSpec, vs *[]domainerr.FieldViolation) {
	phase := strings.TrimSpace(item.Phase)
	action := strings.TrimSpace(item.Action.Type)
	if phase == model.RulePhaseWebSocket && action != "" && action != model.ActionDrop && action != model.ActionBlock {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    path + ".action.type",
			Code:    violationInvalidValue,
			Message: "phase websocket allows only action.type drop or block",
		})
	}
	if (phase == model.RulePhaseRequest || phase == model.RulePhaseResponse) && action == model.ActionBlock {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    path + ".action.type",
			Code:    violationInvalidValue,
			Message: "action.type block is only valid on phase websocket",
		})
	}
	if phase == model.RulePhaseRequest || phase == model.RulePhaseResponse {
		if item.Match.Opcode != "" {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".match.opcode",
				Code:    violationInvalidValue,
				Message: "match.opcode is only valid on phase websocket",
			})
		}
		if item.Match.Direction != "" {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".match.direction",
				Code:    violationInvalidValue,
				Message: "match.direction is only valid on phase websocket",
			})
		}
		if item.Match.PayloadContains != "" {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path + ".match.payloadContains",
				Code:    violationInvalidValue,
				Message: "match.payloadContains is only valid on phase websocket",
			})
		}
	}
	if item.Match.Opcode != "" && !model.KnownRuleOpcode(item.Match.Opcode) {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    path + ".match.opcode",
			Code:    violationInvalidValue,
			Message: "match.opcode must be continuation, text, binary, close, ping, pong, or other",
		})
	}
	if item.Match.Direction != "" && !model.KnownRuleDirection(item.Match.Direction) {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    path + ".match.direction",
			Code:    violationInvalidValue,
			Message: "match.direction must be client or origin",
		})
	}
}

func validateStore(s *model.StoreSpec, vs *[]domainerr.FieldViolation) {
	if s.MaxFlows < 1 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.store.maxFlows", Code: violationInvalidValue, Message: "maxFlows must be ≥ 1"})
	}
	if s.MaxBytes < minStoreMaxBytes {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.store.maxBytes", Code: violationInvalidValue, Message: "maxBytes must be ≥ 1MiB"})
	}
	if s.MaxBodyBytes < minMaxBodyBytes {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.store.maxBodyBytes", Code: violationInvalidValue, Message: "maxBodyBytes must be ≥ 1KiB"})
	}
	if s.MaxBodyBytes > s.MaxBytes && s.MaxBytes > 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.store.maxBodyBytes", Code: violationInvalidValue, Message: "maxBodyBytes must be ≤ maxBytes"})
	}
	switch s.FullPolicy {
	case "", model.FullPolicyReject, model.FullPolicyEvictOldest:
	default:
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.store.fullPolicy",
			Code:    violationInvalidValue,
			Message: "fullPolicy must be reject or evict_oldest",
		})
	}
	if s.MaxWait < 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.store.maxWait", Code: violationInvalidValue, Message: "maxWait must be >= 0"})
	}
	if s.SpillThreshold < 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.store.spillThreshold", Code: violationInvalidValue, Message: "spillThreshold must be >= 0"})
	}
}

func validateManagement(m *model.ManagementSpec, vs *[]domainerr.FieldViolation) {
	switch m.Auth.Mode {
	case "", model.MgmtAuthBearer, model.MgmtAuthDevLoopbackUnauth:
	default:
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.management.auth.mode",
			Code:    violationInvalidValue,
			Message: "management.auth.mode must be bearer or dev-loopback-unauth",
		})
	}
	ids := map[string]string{}
	for i, tok := range m.Auth.Tokens {
		path := indexPath("spec.management.auth.tokens", i)
		id := strings.TrimSpace(tok.ID)
		if id == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: path + ".id", Code: violationEmptyID, Message: "token id is required"})
		} else if prev, ok := ids[id]; ok {
			*vs = append(*vs, domainerr.FieldViolation{Path: path + ".id", Code: violationDuplicateID, Message: "duplicate token id (first at " + prev + ")"})
		} else {
			ids[id] = path + ".id"
		}
		if strings.TrimSpace(tok.SecretFile) == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: path + ".secretFile", Code: violationRequired, Message: "token secretFile is required"})
		} else {
			checkTokenSecretLength(path+".secretFile", tok.SecretFile, vs)
		}
		if strings.TrimSpace(tok.Role) == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: path + ".role", Code: violationRequired, Message: "token role is required"})
		} else if !model.KnownRole(tok.Role) {
			*vs = append(*vs, domainerr.FieldViolation{Path: path + ".role", Code: violationInvalidValue, Message: "role must be viewer, operator, or administrator"})
		}
		for si, sc := range tok.Scopes {
			if !model.KnownScope(sc) {
				*vs = append(*vs, domainerr.FieldViolation{
					Path:    indexPath(path+".scopes", si),
					Code:    violationInvalidValue,
					Message: fmt.Sprintf("unknown scope %q", sc),
				})
			}
		}
	}
	if m.BodyLimit <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.management.bodyLimit", Code: violationInvalidValue, Message: "bodyLimit must be > 0"})
	}
	if m.RequestsPerSecond <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.management.requestsPerSecond", Code: violationInvalidValue, Message: "requestsPerSecond must be > 0"})
	}
	if m.Burst <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.management.burst", Code: violationInvalidValue, Message: "burst must be > 0"})
	}
	if m.MaxConcurrent <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.management.maxConcurrent", Code: violationInvalidValue, Message: "maxConcurrent must be > 0"})
	}
}

func validateObservability(o *model.ObservabilitySpec, vs *[]domainerr.FieldViolation) {
	switch o.LogLevel {
	case "", model.LogLevelDebug, model.LogLevelInfo, model.LogLevelWarn, model.LogLevelError:
	default:
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.observability.logLevel",
			Code:    violationInvalidValue,
			Message: "logLevel must be debug, info, warn, or error",
		})
	}
	validateHostPort("spec.observability.metrics.listen", o.Metrics.Listen, true, vs)
	if o.Audit.Ring < 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.observability.audit.ring", Code: violationInvalidValue, Message: "audit.ring must be >= 0"})
	}
}

func validateFilePair(path string, enabled bool, cert, key string, vs *[]domainerr.FieldViolation) {
	if !enabled {
		if cert != "" || key != "" {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path,
				Code:    violationInvalidValue,
				Message: "certFile/keyFile are illegal when TLS is disabled",
			})
		}
		return
	}
	if strings.TrimSpace(cert) == "" || strings.TrimSpace(key) == "" {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    path,
			Code:    violationRequired,
			Message: "enabled TLS requires certFile and keyFile",
		})
		return
	}
	requireExistingFile(path+".certFile", cert, vs)
	requireExistingFile(path+".keyFile", key, vs)
}

func requireExistingFile(path, file string, vs *[]domainerr.FieldViolation) {
	if _, err := os.Stat(file); err != nil {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    path,
			Code:    violationUnresolved,
			Message: "file does not resolve at load",
		})
	}
}

func validateCAKeyFile(path, file string, vs *[]domainerr.FieldViolation) {
	info, err := os.Stat(file)
	if err != nil {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    path,
			Code:    violationUnresolved,
			Message: "file does not resolve at load",
		})
		return
	}
	if info.Mode().Perm()&0o002 != 0 {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    path,
			Code:    violationInvalidValue,
			Message: "CA key file must not be world-writable",
		})
	}
	b, err := os.ReadFile(file)
	if err != nil {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    path,
			Code:    violationUnresolved,
			Message: "file does not resolve at load",
		})
		return
	}
	if strings.TrimSpace(string(b)) == "" {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    path,
			Code:    violationInvalidValue,
			Message: "CA key PEM must not be empty",
		})
	}
}

// checkTokenSecretLength fails if the file exists and the first secret line
// is shorter than 32 bytes so validate matches serve/FromSpec.
func checkTokenSecretLength(path, file string, vs *[]domainerr.FieldViolation) {
	b, err := os.ReadFile(file)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) < minTokenSecret {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path,
				Code:    violationInvalidValue,
				Message: "token secret must be at least 32 bytes",
			})
		}
		return
	}
	*vs = append(*vs, domainerr.FieldViolation{
		Path:    path,
		Code:    violationInvalidValue,
		Message: "token secret must be at least 32 bytes",
	})
}

// checkRFC1929FileLength fails if the file exists and the first secret line is
// outside RFC 1929's 1–255 octet range.
func checkRFC1929FileLength(path, file, kind string, vs *[]domainerr.FieldViolation) {
	b, err := os.ReadFile(file)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n := len(line)
		if n < minRFC1929Secret || n > maxRFC1929Secret {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    path,
				Code:    violationInvalidValue,
				Message: kind + " must be 1–255 bytes",
			})
		}
		return
	}
	*vs = append(*vs, domainerr.FieldViolation{
		Path:    path,
		Code:    violationInvalidValue,
		Message: kind + " must be 1–255 bytes",
	})
}

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"gopkg.in/yaml.v3"
)

// Decode auto-detects YAML vs JSON and rejects unknown fields. It does not
// normalize or validate.
func Decode(data []byte) (*model.State, error) {
	if len(data) > MaxDocumentBytes {
		return nil, domainerr.ValidationFailed("document exceeds size limit",
			domainerr.FieldViolation{Path: "", Code: violationTooLarge, Message: fmt.Sprintf("document is %d bytes; max is %d", len(data), MaxDocumentBytes)})
	}
	data = stripBOM(bytes.TrimSpace(data))
	if len(data) == 0 {
		return nil, domainerr.ValidationFailed("empty document",
			domainerr.FieldViolation{Path: "", Code: violationRequired, Message: "document is empty"})
	}
	if !utf8.Valid(data) {
		return nil, domainerr.ValidationFailed("document is not UTF-8",
			domainerr.FieldViolation{Path: "", Code: violationInvalidValue, Message: "document must be UTF-8"})
	}
	if looksLikeJSON(data) {
		return decodeJSON(data)
	}
	return decodeYAML(data)
}

// DecodeYAML decodes a YAML document with unknown-field rejection.
func DecodeYAML(data []byte) (*model.State, error) {
	if len(data) > MaxDocumentBytes {
		return nil, domainerr.ValidationFailed("document exceeds size limit",
			domainerr.FieldViolation{Path: "", Code: violationTooLarge, Message: "document exceeds size limit"})
	}
	return decodeYAML(stripBOM(data))
}

// DecodeJSON decodes a JSON document with unknown-field rejection.
func DecodeJSON(data []byte) (*model.State, error) {
	if len(data) > MaxDocumentBytes {
		return nil, domainerr.ValidationFailed("document exceeds size limit",
			domainerr.FieldViolation{Path: "", Code: violationTooLarge, Message: "document exceeds size limit"})
	}
	return decodeJSON(stripBOM(data))
}

func decodeYAML(data []byte) (*model.State, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var node yaml.Node
	if err := dec.Decode(&node); err != nil {
		if err == io.EOF {
			return nil, domainerr.ValidationFailed("empty document",
				domainerr.FieldViolation{Path: "", Code: violationRequired, Message: "document is empty"})
		}
		return nil, mapYAMLKnownFieldsError(err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, domainerr.ValidationFailed("trailing YAML document",
			domainerr.FieldViolation{Path: "", Code: violationInvalidValue, Message: "document contains more than one YAML value"})
	}
	if vs := inspectYAMLNode(&node, ""); len(vs) > 0 {
		return nil, domainerr.ValidationFailed("invalid YAML document", vs...)
	}

	// KnownFields(true) on a typed document rejects unknown top-level keys.
	topDec := yaml.NewDecoder(bytes.NewReader(data))
	topDec.KnownFields(true)
	var top struct {
		APIVersion string         `yaml:"apiVersion"`
		Kind       string         `yaml:"kind"`
		Metadata   map[string]any `yaml:"metadata"`
		Spec       map[string]any `yaml:"spec"`
	}
	if err := topDec.Decode(&top); err != nil {
		return nil, mapYAMLKnownFieldsError(err)
	}

	var raw any
	if err := node.Decode(&raw); err != nil {
		return nil, domainerr.ValidationFailed("YAML decode failed",
			domainerr.FieldViolation{Path: "", Code: violationInvalidValue, Message: err.Error()})
	}
	raw = stringifyKeys(raw)
	return decodeRaw(raw)
}

func decodeJSON(data []byte) (*model.State, error) {
	var raw any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, domainerr.ValidationFailed("JSON decode failed",
			domainerr.FieldViolation{Path: "", Code: violationInvalidValue, Message: err.Error()})
	}
	if dec.More() {
		return nil, domainerr.ValidationFailed("trailing JSON value",
			domainerr.FieldViolation{Path: "", Code: violationInvalidValue, Message: "document contains more than one JSON value"})
	}
	return decodeRaw(raw)
}

func decodeRaw(raw any) (*model.State, error) {
	if vs := reservedFields(raw, ""); len(vs) > 0 {
		return nil, domainerr.ValidationFailed("reserved fields", vs...)
	}
	applyDecodeDefaults(raw)
	if vs := convertDurations(raw, ""); len(vs) > 0 {
		return nil, domainerr.ValidationFailed("invalid durations", vs...)
	}
	if vs := convertByteSizes(raw, ""); len(vs) > 0 {
		return nil, domainerr.ValidationFailed("invalid byte sizes", vs...)
	}
	if vs := unknownFields(raw, reflect.TypeOf(model.State{}), ""); len(vs) > 0 {
		return nil, domainerr.ValidationFailed("unknown fields", vs...)
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, domainerr.ValidationFailed("re-encode failed",
			domainerr.FieldViolation{Path: "", Code: violationInvalidValue, Message: err.Error()})
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var st model.State
	if err := dec.Decode(&st); err != nil {
		return nil, mapJSONDecodeError(err)
	}
	return &st, nil
}

func mapJSONDecodeError(err error) error {
	msg := err.Error()
	if strings.Contains(msg, "unknown field") {
		field := msg
		if i := strings.Index(msg, `"`); i >= 0 {
			if j := strings.LastIndex(msg, `"`); j > i {
				field = msg[i+1 : j]
			}
		}
		return domainerr.ValidationFailed("unknown fields",
			domainerr.FieldViolation{Path: field, Code: violationUnknownField, Message: "unknown field"})
	}
	return domainerr.ValidationFailed("JSON decode failed",
		domainerr.FieldViolation{Path: "", Code: violationInvalidValue, Message: msg})
}

func mapYAMLKnownFieldsError(err error) error {
	msg := err.Error()
	if strings.Contains(msg, "not found") || strings.Contains(msg, "unknown field") {
		field := msg
		if i := strings.Index(msg, `"`); i >= 0 {
			if j := strings.Index(msg[i+1:], `"`); j >= 0 {
				field = msg[i+1 : i+1+j]
			}
		}
		return domainerr.ValidationFailed("unknown fields",
			domainerr.FieldViolation{Path: field, Code: violationUnknownField, Message: fmt.Sprintf("unknown field %q", field)})
	}
	return domainerr.ValidationFailed("YAML decode failed",
		domainerr.FieldViolation{Path: "", Code: violationInvalidValue, Message: msg})
}

func looksLikeJSON(data []byte) bool {
	data = bytes.TrimSpace(data)
	return len(data) > 0 && (data[0] == '{' || data[0] == '[')
}

func stripBOM(data []byte) []byte {
	return bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
}

func stringifyKeys(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, child := range x {
			out[k] = stringifyKeys(child)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, child := range x {
			out[fmt.Sprint(k)] = stringifyKeys(child)
		}
		return out
	case []any:
		for i, child := range x {
			x[i] = stringifyKeys(child)
		}
		return x
	default:
		return v
	}
}

// applyDecodeDefaults injects defaults that cannot be recovered from a Go zero
// value after unmarshal (bool true defaults) and the standalone loopback binds.
func applyDecodeDefaults(v any) {
	root, ok := v.(map[string]any)
	if !ok {
		return
	}
	spec := ensureMap(root, "spec")
	if spec == nil {
		return
	}

	listeners := ensureMap(spec, "listeners")
	proxyL := ensureMap(listeners, "proxy")
	setDefaultAddress(proxyL, DefaultProxyAddress)
	mgmtL := ensureMap(listeners, "management")
	setDefaultAddress(mgmtL, DefaultMgmtAddress)
	setDefault(mgmtL, "restPath", DefaultRESTPath)
	setDefault(mgmtL, "mcpPath", DefaultMCPPath)
	mgmtTLS := ensureMap(mgmtL, "tls")
	setDefault(mgmtTLS, "enabled", false)
	setDefault(mgmtTLS, "certFile", "")
	setDefault(mgmtTLS, "keyFile", "")

	proxy := ensureMap(spec, "proxy")
	setDefault(proxy, "hostname", DefaultProxyHostname)
	adm := ensureMap(proxy, "admission")
	setDefault(adm, "maxSessions", DefaultMaxSessions)
	setDefault(adm, "maxSessionsPerIP", DefaultMaxSessionsPerIP)
	setDefault(adm, "maxInFlight", DefaultMaxInFlight)
	setDefault(adm, "maxInFlightBytes", "64MiB")
	setDefault(adm, "sessionTimeout", "10m")
	setDefault(adm, "idleTimeout", "120s")
	setDefault(adm, "headerTimeout", "10s")
	setDefault(adm, "dialTimeout", "10s")
	setDefault(adm, "upstreamTimeout", "60s")
	targets := ensureMap(proxy, "targets")
	setDefault(targets, "denyCloudMetadata", true)
	setDefault(targets, "denyLinkLocal", true)
	setDefault(targets, "allowLoopback", true)
	setDefault(targets, "allowHosts", []any{})
	setDefault(targets, "denyHosts", []any{})

	tls := ensureMap(spec, "tls")
	setDefault(tls, "intercept", false)
	setDefault(tls, "hosts", []any{})
	setDefaultPorts(tls)
	ca := ensureMap(tls, "ca")
	setDefault(ca, "mode", model.CAModeGenerate)
	setDefault(ca, "certFile", "")
	setDefault(ca, "keyFile", "")
	upstream := ensureMap(tls, "upstream")
	setDefault(upstream, "insecureSkipVerify", false)
	setDefault(upstream, "extraCAFiles", []any{})

	rules := ensureMap(spec, "rules")
	setDefault(rules, "enabled", false)
	setDefault(rules, "items", []any{})
	if items, ok := rules["items"].([]any); ok {
		for _, item := range items {
			if m, ok := item.(map[string]any); ok {
				setDefault(m, "enabled", true)
			}
		}
	}

	store := ensureMap(spec, "store")
	setDefault(store, "maxFlows", DefaultMaxFlows)
	setDefault(store, "maxBytes", "256MiB")
	setDefault(store, "maxBodyBytes", "1MiB")
	setDefault(store, "fullPolicy", model.FullPolicyReject)
	setDefault(store, "maxWait", "60s")
	setDefault(store, "spillDirectory", "")
	setDefault(store, "spillThreshold", "256KiB")

	ui := ensureMap(spec, "ui")
	setDefault(ui, "enabled", true)

	mgmt := ensureMap(spec, "management")
	authM := ensureMap(mgmt, "auth")
	setDefault(authM, "mode", model.MgmtAuthBearer)
	setDefault(authM, "tokens", []any{})
	mcp := ensureMap(mgmt, "mcp")
	setDefault(mcp, "allowLegacyClients", false)
	setDefault(mgmt, "originAllowlist", []any{})
	setDefault(mgmt, "bodyLimit", "1MiB")
	setDefault(mgmt, "requestsPerSecond", DefaultRequestsPerSecond)
	setDefault(mgmt, "burst", DefaultBurst)
	setDefault(mgmt, "maxConcurrent", DefaultMaxConcurrent)

	obs := ensureMap(spec, "observability")
	setDefault(obs, "logLevel", model.LogLevelInfo)
	metrics := ensureMap(obs, "metrics")
	setDefault(metrics, "listen", DefaultMetricsListen)
	setDefault(metrics, "publicPath", false)
	audit := ensureMap(obs, "audit")
	setDefault(audit, "ring", DefaultAuditRing)
}

func ensureMap(parent map[string]any, key string) map[string]any {
	if parent == nil {
		return nil
	}
	if m, ok := parent[key].(map[string]any); ok {
		return m
	}
	// Present-but-null (YAML `targets:`, JSON `"targets": null`) is absent.
	// A non-map value is a type error; leave it for later decode rejection.
	if v, exists := parent[key]; exists && v != nil {
		return nil
	}
	m := map[string]any{}
	parent[key] = m
	return m
}

func setDefault(obj map[string]any, key string, val any) {
	if obj == nil {
		return
	}
	if _, exists := obj[key]; !exists {
		obj[key] = val
	}
}

func setDefaultAddress(obj map[string]any, def string) {
	if obj == nil {
		return
	}
	if v, ok := obj["address"].(string); ok {
		if strings.TrimSpace(v) != "" {
			return
		}
	} else if _, exists := obj["address"]; exists {
		return
	}
	obj["address"] = def
}

func setDefaultPorts(tls map[string]any) {
	if tls == nil {
		return
	}
	if v, ok := tls["ports"].([]any); ok {
		if len(v) == 0 {
			tls["ports"] = []any{defaultTLSPort}
		}
		return
	}
	if _, exists := tls["ports"]; exists {
		return
	}
	tls["ports"] = []any{defaultTLSPort}
}

func inspectYAMLNode(n *yaml.Node, path string) []domainerr.FieldViolation {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return []domainerr.FieldViolation{{
			Path:    path,
			Code:    violationInvalidValue,
			Message: "YAML aliases and anchors are not allowed",
		}}
	}
	if n.Kind == yaml.DocumentNode {
		var vs []domainerr.FieldViolation
		for _, c := range n.Content {
			vs = append(vs, inspectYAMLNode(c, path)...)
		}
		return vs
	}
	if n.Kind == yaml.MappingNode {
		var vs []domainerr.FieldViolation
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			v := n.Content[i+1]
			name := k.Value
			if name == "<<" {
				vs = append(vs, domainerr.FieldViolation{
					Path:    joinPath(path, name),
					Code:    violationInvalidValue,
					Message: "YAML merge keys are not allowed",
				})
				continue
			}
			if seen[name] {
				vs = append(vs, domainerr.FieldViolation{
					Path:    joinPath(path, name),
					Code:    violationDuplicateKey,
					Message: fmt.Sprintf("duplicate key %q", name),
				})
			}
			seen[name] = true
			if !isFreeFormStringMap(path) {
				if why := reservedReason(normalizeKey(name)); why != "" {
					vs = append(vs, domainerr.FieldViolation{
						Path:    joinPath(path, name),
						Code:    violationReservedName,
						Message: fmt.Sprintf("reserved key %q %s — not a 1.0 LabMITM surface", name, why),
					})
				}
			}
			vs = append(vs, inspectYAMLNode(k, joinPath(path, name))...)
			vs = append(vs, inspectYAMLNode(v, joinPath(path, name))...)
		}
		return vs
	}
	if n.Kind == yaml.SequenceNode {
		var vs []domainerr.FieldViolation
		for i, c := range n.Content {
			vs = append(vs, inspectYAMLNode(c, indexPath(path, i))...)
		}
		return vs
	}
	return nil
}

func unknownFields(val any, typ reflect.Type, path string) []domainerr.FieldViolation {
	if val == nil || typ == nil {
		return nil
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		if typ == reflect.TypeOf(time.Time{}) {
			return nil
		}
		obj, ok := val.(map[string]any)
		if !ok {
			return nil
		}
		fields := jsonFieldMap(typ)
		var vs []domainerr.FieldViolation
		for k, child := range obj {
			ft, ok := fields[k]
			if !ok {
				vs = append(vs, domainerr.FieldViolation{
					Path:    joinPath(path, k),
					Code:    violationUnknownField,
					Message: fmt.Sprintf("unknown field %q", k),
				})
				continue
			}
			vs = append(vs, unknownFields(child, ft, joinPath(path, k))...)
		}
		return vs
	case reflect.Slice, reflect.Array:
		arr, ok := val.([]any)
		if !ok {
			return nil
		}
		var vs []domainerr.FieldViolation
		for i, child := range arr {
			vs = append(vs, unknownFields(child, typ.Elem(), indexPath(path, i))...)
		}
		return vs
	case reflect.Map:
		return nil
	default:
		return nil
	}
}

func jsonFieldMap(typ reflect.Type) map[string]reflect.Type {
	out := make(map[string]reflect.Type)
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" {
			continue
		}
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		out[name] = f.Type
	}
	return out
}

func joinPath(base, key string) string {
	if base == "" {
		return key
	}
	return base + "." + key
}

func indexPath(base string, i int) string {
	return fmt.Sprintf("%s[%d]", base, i)
}

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestSchemaPublished(t *testing.T) {
	b, err := SchemaBytes()
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	if root["$id"] != "https://labmitm.dev/schema/v1alpha1" {
		t.Fatalf("$id=%v", root["$id"])
	}
	if root["additionalProperties"] != false {
		t.Fatal("root additionalProperties must be false")
	}
	defs, _ := root["$defs"].(map[string]any)
	required := []string{
		"spec", "listeners", "proxy", "tls", "rules", "store", "ui", "management", "observability",
		"admission", "targets", "ca", "upstream", "mgmtAuth", "token", "rule",
		"originalDest", "protocols", "http2", "websocket", "protocolGate", "userPass", "userPassUser", "compat", "flowRESTCompat",
	}
	for _, name := range required {
		def, ok := defs[name].(map[string]any)
		if !ok {
			t.Fatalf("missing $defs.%s", name)
			continue
		}
		if def["additionalProperties"] != false {
			t.Fatalf("$defs.%s additionalProperties=%v want false", name, def["additionalProperties"])
		}
	}
	upstream, _ := defs["upstream"].(map[string]any)
	props, _ := upstream["properties"].(map[string]any)
	if _, ok := props["verify"]; ok {
		t.Fatal("schema must not list tls.upstream.verify as an input field")
	}
	if _, ok := props["insecureSkipVerify"]; !ok {
		t.Fatal("schema must list insecureSkipVerify")
	}
}

func TestSchemaListsModelJSONFields(t *testing.T) {
	b, err := SchemaBytes()
	if err != nil {
		t.Fatal(err)
	}
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	schemaKeys := collectSchemaPropertyNames(raw)
	for _, sample := range []any{
		model.State{}, model.Spec{}, model.ListenersSpec{}, model.ProxyListenerSpec{},
		model.MgmtListenerSpec{}, model.ListenerTLS{}, model.ProxySpec{}, model.AdmissionSpec{},
		model.TargetsSpec{}, model.TLSSpec{}, model.CASpec{}, model.TLSUpstreamSpec{},
		model.RulesSpec{}, model.RuleSpec{}, model.RuleMatchSpec{}, model.RuleActionSpec{},
		model.RuleHeadersSpec{}, model.RuleBodySpec{}, model.RuleBreakpointSpec{},
		model.RuleSilentSpec{}, model.RuleHangSpec{}, model.RuleRedirectSpec{},
		model.StoreSpec{}, model.UISpec{}, model.ManagementSpec{},
		model.MgmtAuthSpec{}, model.TokenSpec{}, model.MCPSpec{},
		model.ObservabilitySpec{}, model.MetricsSpec{}, model.AuditSpec{},
		model.OriginalDestListenerSpec{}, model.ProtocolsSpec{}, model.HTTP2Spec{},
		model.WebSocketSpec{}, model.ProtocolGateSpec{}, model.UserPassSpec{}, model.UserPassUserSpec{},
		model.CompatSpec{}, model.FlowRESTCompatSpec{},
	} {
		rt := reflect.TypeOf(sample)
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			tag := f.Tag.Get("json")
			name, _, _ := strings.Cut(tag, ",")
			if name == "" || name == "-" {
				continue
			}
			if !schemaKeys[name] {
				t.Errorf("model %s.%s json %q missing from schema", rt.Name(), f.Name, name)
			}
		}
	}
}

func collectSchemaPropertyNames(v any) map[string]bool {
	out := map[string]bool{}
	var walk func(any)
	walk = func(x any) {
		m, ok := x.(map[string]any)
		if !ok {
			if arr, ok := x.([]any); ok {
				for _, c := range arr {
					walk(c)
				}
			}
			return
		}
		if props, ok := m["properties"].(map[string]any); ok {
			for k, child := range props {
				out[k] = true
				walk(child)
			}
		}
		for _, child := range m {
			walk(child)
		}
	}
	walk(v)
	return out
}

func TestSchemaFileExistsAtPublishedPath(t *testing.T) {
	p := filepath.Join(repoRoot(t), filepath.FromSlash(SchemaRelPath))
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
}

func TestGoldenCanonicalJSONMatchesSchema(t *testing.T) {
	st, err := LoadFile(testdata(t, "valid", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CanonicalJSON(st)
	if err != nil {
		t.Fatal(err)
	}
	assertCanonicalMatchesSchema(t, raw)
}

func assertCanonicalMatchesSchema(t *testing.T, raw []byte) {
	t.Helper()
	schemaBytes, err := SchemaBytes()
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatal(err)
	}
	var inst any
	if err := json.Unmarshal(raw, &inst); err != nil {
		t.Fatal(err)
	}
	if err := checkJSONSchema(inst, schema, schema, ""); err != nil {
		t.Fatalf("canonical JSON failed published schema: %v\n%s", err, raw)
	}
}

func checkJSONSchema(inst any, sch, root map[string]any, path string) error {
	if ref, ok := sch["$ref"].(string); ok {
		def, err := resolveSchemaRef(root, ref)
		if err != nil {
			return err
		}
		return checkJSONSchema(inst, def, root, path)
	}
	if c, ok := sch["const"]; ok {
		if !schemaValuesEqual(inst, c) {
			return fmt.Errorf("%s: want const %v, got %v", pathOrRoot(path), c, inst)
		}
	}
	if enum, ok := sch["enum"].([]any); ok {
		okv := false
		for _, e := range enum {
			if schemaValuesEqual(inst, e) {
				okv = true
				break
			}
		}
		if !okv {
			return fmt.Errorf("%s: %v not in enum %v", pathOrRoot(path), inst, enum)
		}
	}
	if typ, ok := sch["type"].(string); ok {
		if err := checkSchemaType(inst, typ, path); err != nil {
			return err
		}
	}
	switch inst := inst.(type) {
	case map[string]any:
		if req, ok := sch["required"].([]any); ok {
			for _, r := range req {
				key, _ := r.(string)
				if _, ok := inst[key]; !ok {
					return fmt.Errorf("%s: missing required %q", pathOrRoot(path), key)
				}
			}
		}
		props, _ := sch["properties"].(map[string]any)
		add := sch["additionalProperties"]
		for k, child := range inst {
			ps, ok := props[k].(map[string]any)
			if !ok {
				if add == false {
					return fmt.Errorf("%s: additional property %q", pathOrRoot(path), k)
				}
				continue
			}
			if err := checkJSONSchema(child, ps, root, joinPath(path, k)); err != nil {
				return err
			}
		}
	case []any:
		if items, ok := sch["items"].(map[string]any); ok {
			for i, child := range inst {
				if err := checkJSONSchema(child, items, root, indexPath(path, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func resolveSchemaRef(root map[string]any, ref string) (map[string]any, error) {
	const p = "#/$defs/"
	if !strings.HasPrefix(ref, p) {
		return nil, fmt.Errorf("unsupported $ref %q", ref)
	}
	defs, _ := root["$defs"].(map[string]any)
	def, ok := defs[strings.TrimPrefix(ref, p)].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unknown $ref %q", ref)
	}
	return def, nil
}

func checkSchemaType(inst any, typ, path string) error {
	switch typ {
	case "object":
		if _, ok := inst.(map[string]any); !ok && inst != nil {
			return fmt.Errorf("%s: want object, got %T", pathOrRoot(path), inst)
		}
	case "array":
		if _, ok := inst.([]any); !ok && inst != nil {
			return fmt.Errorf("%s: want array, got %T", pathOrRoot(path), inst)
		}
	case "string":
		if _, ok := inst.(string); !ok {
			return fmt.Errorf("%s: want string, got %T", pathOrRoot(path), inst)
		}
	case "boolean":
		if _, ok := inst.(bool); !ok {
			return fmt.Errorf("%s: want boolean, got %T", pathOrRoot(path), inst)
		}
	case "integer":
		switch n := inst.(type) {
		case float64:
			if n != float64(int64(n)) {
				return fmt.Errorf("%s: want integer, got %v", pathOrRoot(path), n)
			}
		case json.Number:
			if _, err := n.Int64(); err != nil {
				return fmt.Errorf("%s: want integer, got %v", pathOrRoot(path), n)
			}
		default:
			return fmt.Errorf("%s: want integer, got %T", pathOrRoot(path), inst)
		}
	case "number":
		switch inst.(type) {
		case float64, json.Number:
		default:
			return fmt.Errorf("%s: want number, got %T", pathOrRoot(path), inst)
		}
	}
	return nil
}

func schemaValuesEqual(a, b any) bool {
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		return as == bs
	}
	return reflect.DeepEqual(a, b)
}

func pathOrRoot(p string) string {
	if p == "" {
		return "<root>"
	}
	return p
}

func TestDurationFormatRoundTrip(t *testing.T) {
	cases := []time.Duration{
		0, time.Second, 30 * time.Second, time.Minute, 5 * time.Minute,
		time.Hour, 24 * time.Hour, 100 * time.Millisecond,
	}
	for _, d := range cases {
		s := FormatDuration(d)
		got, err := time.ParseDuration(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if got != d {
			t.Fatalf("%s parsed to %s want %s", s, got, d)
		}
	}
}

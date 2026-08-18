package config

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestDecodeDefaultsYAML(t *testing.T) {
	st, err := Decode([]byte(mustLoad(t, "valid", "defaults.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	if st.APIVersion != model.APIVersionV1Alpha1 || st.Kind != model.KindLabMITM {
		t.Fatalf("api=%q kind=%q", st.APIVersion, st.Kind)
	}
	if st.Metadata.Name != "lab-proxy" {
		t.Fatalf("name=%q", st.Metadata.Name)
	}
	if !st.Spec.UI.Enabled {
		t.Fatal("omitted ui.enabled must materialize true at decode")
	}
	if !st.Spec.Proxy.Targets.DenyCloudMetadata || !st.Spec.Proxy.Targets.DenyLinkLocal || !st.Spec.Proxy.Targets.AllowLoopback {
		t.Fatal("omitted target guards must materialize fail-closed defaults")
	}
	if st.Spec.Listeners.Proxy.Address != DefaultProxyAddress {
		t.Fatalf("proxy addr=%q", st.Spec.Listeners.Proxy.Address)
	}
	if st.Spec.Listeners.Management.Address != DefaultMgmtAddress {
		t.Fatalf("mgmt addr=%q", st.Spec.Listeners.Management.Address)
	}
	if st.Spec.Observability.Metrics.Listen != DefaultMetricsListen {
		t.Fatalf("listen=%q", st.Spec.Observability.Metrics.Listen)
	}
	if st.Spec.TLS.Intercept {
		t.Fatal("omitted tls.intercept must stay false")
	}
	if len(st.Spec.TLS.Ports) != 1 || st.Spec.TLS.Ports[0] != 443 {
		t.Fatalf("ports=%v want [443]", st.Spec.TLS.Ports)
	}
	if st.Spec.Management.Auth.Mode != model.MgmtAuthBearer {
		t.Fatalf("auth.mode=%q", st.Spec.Management.Auth.Mode)
	}
}

func TestDecodeJSONUnknownField(t *testing.T) {
	_, err := DecodeJSON([]byte(`{"apiVersion":"labmitm.dev/v1alpha1","kind":"LabMITM","metadata":{"name":"x"},"spec":{"nope":1}}`))
	_ = requireValidation(t, err, violationUnknownField)
}

func TestDecodeUnknownFieldEveryLevel(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		path string
	}{
		{"root", `{"apiVersion":"labmitm.dev/v1alpha1","kind":"LabMITM","metadata":{"name":"x"},"extra":true,"spec":{}}`, "extra"},
		{"metadata", `{"apiVersion":"labmitm.dev/v1alpha1","kind":"LabMITM","metadata":{"name":"x","nope":1},"spec":{}}`, "metadata.nope"},
		{"spec", `{"apiVersion":"labmitm.dev/v1alpha1","kind":"LabMITM","metadata":{"name":"x"},"spec":{"nope":1}}`, "spec.nope"},
		{"proxy", `{"apiVersion":"labmitm.dev/v1alpha1","kind":"LabMITM","metadata":{"name":"x"},"spec":{"proxy":{"zzz":1}}}`, "spec.proxy.zzz"},
		{"tls-upstream-verify", `{"apiVersion":"labmitm.dev/v1alpha1","kind":"LabMITM","metadata":{"name":"x"},"spec":{"tls":{"upstream":{"verify":true}}}}`, "spec.tls.upstream.verify"},
		{"store", `{"apiVersion":"labmitm.dev/v1alpha1","kind":"LabMITM","metadata":{"name":"x"},"spec":{"store":{"foo":true}}}`, "spec.store.foo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeJSON([]byte(tc.doc))
			de := requireValidation(t, err, violationUnknownField)
			found := false
			for _, v := range de.FieldViolations {
				if v.Path == tc.path {
					found = true
				}
			}
			if !found {
				t.Fatalf("want path %q in %+v", tc.path, de.FieldViolations)
			}
		})
	}
}

func TestDecodeYAMLCommentsDropped(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\n# keep me\nmetadata:\n  name: x\nspec: {}\n"
	st, err := DecodeYAML([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	y, err := CanonicalYAML(st)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(y), "keep me") {
		t.Fatalf("comment preserved:\n%s", y)
	}
}

func TestDecodeUIEnabledExplicitFalse(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  ui:\n    enabled: false\n  observability:\n    metrics:\n      listen: \"\"\n"
	st, err := Decode([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.UI.Enabled {
		t.Fatal("explicit ui.enabled: false was overwritten")
	}
	if st.Spec.Observability.Metrics.Listen != "" {
		t.Fatalf("explicit empty metrics.listen was overwritten: %q", st.Spec.Observability.Metrics.Listen)
	}
}

func TestDecodeRejectsTrailingDocuments(t *testing.T) {
	yamlDoc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: a\nspec: {}\n---\nkind: LabMITM\n"
	_, err := DecodeYAML([]byte(yamlDoc))
	_ = requireValidation(t, err, violationInvalidValue)

	jsonDoc := `{"apiVersion":"labmitm.dev/v1alpha1","kind":"LabMITM","metadata":{"name":"a"},"spec":{}}{"x":1}`
	_, err = DecodeJSON([]byte(jsonDoc))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestDecodeRejectsUnitlessDurationAndSize(t *testing.T) {
	_, err := Decode([]byte(mustLoad(t, "invalid", "bare-duration.yaml")))
	_ = requireValidation(t, err, violationInvalidValue)
	_, err = Decode([]byte(mustLoad(t, "invalid", "bare-bytes.yaml")))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestDecodeRejectsEmptyAndTooLarge(t *testing.T) {
	if _, err := Decode(nil); err == nil {
		t.Fatal("empty")
	}
	big := make([]byte, MaxDocumentBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	if _, err := Decode(big); err == nil {
		t.Fatal("too large")
	}
}

func TestDecodeJSONRoundTripSample(t *testing.T) {
	st, err := Load([]byte(mustLoad(t, "valid", "defaults.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CanonicalJSON(st)
	if err != nil {
		t.Fatal(err)
	}
	st2, err := Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	r1, err := Revision(st)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Revision(st2)
	if err != nil {
		t.Fatal(err)
	}
	if r1 != r2 {
		t.Fatalf("export/reimport revision %s != %s", r1, r2)
	}
}

func TestDecodeEmptyAddressMaterializesLoopback(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  listeners:\n    proxy:\n      address: \"\"\n    management:\n      address: \"\"\n"
	st, err := Load([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.Listeners.Proxy.Address != DefaultProxyAddress {
		t.Fatalf("proxy=%q", st.Spec.Listeners.Proxy.Address)
	}
	if st.Spec.Listeners.Management.Address != DefaultMgmtAddress {
		t.Fatalf("mgmt=%q", st.Spec.Listeners.Management.Address)
	}
}

func TestDecodeNullTargetsAndUIGetFailClosedDefaults(t *testing.T) {
	yamlDoc := mustLoad(t, "valid", "null-targets.yaml")
	st, err := Load([]byte(yamlDoc))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Spec.Proxy.Targets.DenyCloudMetadata || !st.Spec.Proxy.Targets.DenyLinkLocal || !st.Spec.Proxy.Targets.AllowLoopback {
		t.Fatalf("YAML null targets: denyCloud=%v denyLink=%v allowLoop=%v",
			st.Spec.Proxy.Targets.DenyCloudMetadata, st.Spec.Proxy.Targets.DenyLinkLocal, st.Spec.Proxy.Targets.AllowLoopback)
	}
	if !st.Spec.UI.Enabled {
		t.Fatal("YAML null ui must materialize enabled=true")
	}

	jsonDoc := `{"apiVersion":"labmitm.dev/v1alpha1","kind":"LabMITM","metadata":{"name":"x"},"spec":{"proxy":{"targets":null},"ui":null}}`
	st, err = Load([]byte(jsonDoc))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Spec.Proxy.Targets.DenyCloudMetadata || !st.Spec.Proxy.Targets.DenyLinkLocal || !st.Spec.Proxy.Targets.AllowLoopback {
		t.Fatalf("JSON null targets: denyCloud=%v denyLink=%v allowLoop=%v",
			st.Spec.Proxy.Targets.DenyCloudMetadata, st.Spec.Proxy.Targets.DenyLinkLocal, st.Spec.Proxy.Targets.AllowLoopback)
	}
	if !st.Spec.UI.Enabled {
		t.Fatal("JSON null ui must materialize enabled=true")
	}
}

func TestDecodeEmptyPortsMaterialize443(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  tls:\n    ports: []\n"
	st, err := Load([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Spec.TLS.Ports) != 1 || st.Spec.TLS.Ports[0] != 443 {
		t.Fatalf("ports=%v", st.Spec.TLS.Ports)
	}
}

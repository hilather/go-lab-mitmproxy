package config

import (
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestNormalizeMaterializesDefaults(t *testing.T) {
	st, err := Load([]byte(mustLoad(t, "valid", "defaults.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.Listeners.Proxy.Address != DefaultProxyAddress {
		t.Fatalf("proxy addr=%q", st.Spec.Listeners.Proxy.Address)
	}
	if st.Spec.Listeners.Management.Address != DefaultMgmtAddress {
		t.Fatalf("mgmt addr=%q", st.Spec.Listeners.Management.Address)
	}
	if st.Spec.Proxy.Hostname != DefaultProxyHostname {
		t.Fatalf("hostname=%q", st.Spec.Proxy.Hostname)
	}
	if st.Spec.Store.MaxFlows != DefaultMaxFlows {
		t.Fatalf("maxFlows=%d", st.Spec.Store.MaxFlows)
	}
	if st.Spec.Store.MaxBytes != DefaultStoreMaxBytes {
		t.Fatalf("maxBytes=%d", st.Spec.Store.MaxBytes)
	}
	if st.Spec.Store.MaxBodyBytes != DefaultMaxBodyBytes {
		t.Fatalf("maxBodyBytes=%d", st.Spec.Store.MaxBodyBytes)
	}
	if st.Spec.Store.FullPolicy != model.FullPolicyReject {
		t.Fatalf("fullPolicy=%q", st.Spec.Store.FullPolicy)
	}
	if !st.Spec.UI.Enabled {
		t.Fatal("ui.enabled default")
	}
	if st.Spec.Management.Auth.Mode != model.MgmtAuthBearer {
		t.Fatalf("auth.mode=%q", st.Spec.Management.Auth.Mode)
	}
	if st.Spec.TLS.CA.Mode != model.CAModeGenerate {
		t.Fatalf("ca.mode=%q", st.Spec.TLS.CA.Mode)
	}
	if st.Spec.Rules.Items == nil {
		t.Fatal("rules.items must be empty slice, not nil")
	}
	if st.Spec.Management.Auth.Tokens == nil {
		t.Fatal("tokens must be empty slice, not nil")
	}
	if st.Spec.Listeners.Proxy.AcceptSOCKS5 || st.Spec.Listeners.Proxy.AcceptSOCKS4 {
		t.Fatal("SOCKS accept flags default off")
	}
	if st.Spec.Listeners.OriginalDestination.Enabled {
		t.Fatal("originalDestination.enabled default off")
	}
	if st.Spec.Protocols.HTTP2.Enabled {
		t.Fatal("protocols.http2.enabled default off")
	}
	if st.Spec.Compat.FlowREST.Enabled {
		t.Fatal("compat.flowREST.enabled default off")
	}
	if st.Spec.Proxy.Admission.MaxConcurrentStreams != DefaultMaxConcurrentStreams {
		t.Fatalf("maxConcurrentStreams=%d", st.Spec.Proxy.Admission.MaxConcurrentStreams)
	}
}

func TestNormalizeEnabledOrigDestEmptyAddress(t *testing.T) {
	st, err := LoadFile(testdata(t, "valid", "original-destination.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Spec.Listeners.OriginalDestination.Enabled {
		t.Fatal("enabled")
	}
	if st.Spec.Listeners.OriginalDestination.Address != DefaultOrigDestAddress {
		t.Fatalf("addr=%q", st.Spec.Listeners.OriginalDestination.Address)
	}
}

func TestNormalizeEnabledCompatEmptyPrefix(t *testing.T) {
	st, err := LoadFile(testdata(t, "valid", "compat-flow-rest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Spec.Compat.FlowREST.Enabled {
		t.Fatal("enabled")
	}
	if st.Spec.Compat.FlowREST.PathPrefix != DefaultCompatPathPrefix {
		t.Fatalf("prefix=%q", st.Spec.Compat.FlowREST.PathPrefix)
	}
}

func TestNormalizeAcceptSOCKS5CamelCase(t *testing.T) {
	st, err := LoadFile(testdata(t, "valid", "accept-socks5.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Spec.Listeners.Proxy.AcceptSOCKS5 {
		t.Fatal("acceptSOCKS5")
	}
	if st.Spec.Listeners.Proxy.AcceptSOCKS4 {
		t.Fatal("acceptSOCKS4 stayed off")
	}
}

func TestLoadExplicitZeroMaxConcurrentStreams(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  proxy:\n    admission:\n      maxConcurrentStreams: 0\n"
	st, err := Load([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.Proxy.Admission.MaxConcurrentStreams != DefaultMaxConcurrentStreams {
		t.Fatalf("maxConcurrentStreams=%d want %d", st.Spec.Proxy.Admission.MaxConcurrentStreams, DefaultMaxConcurrentStreams)
	}
}

func TestNormalizeHTTP2Flag(t *testing.T) {
	st, err := LoadFile(testdata(t, "valid", "protocols-http2.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Spec.Protocols.HTTP2.Enabled {
		t.Fatal("http2")
	}
}

func TestNormalizeDoesNotMutateInput(t *testing.T) {
	st, err := Decode([]byte(mustLoad(t, "valid", "defaults.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	n, err := Normalize(st)
	if err != nil {
		t.Fatal(err)
	}
	st.Spec.Proxy.Hostname = "mutated"
	if n.Spec.Proxy.Hostname == "mutated" {
		t.Fatal("Normalize mutated caller")
	}
}

func TestNormalizeNil(t *testing.T) {
	_, err := Normalize(nil)
	_ = requireValidation(t, err, violationRequired)
}

func TestImplementationNoteDefaults(t *testing.T) {
	if DefaultProxyAddress != "127.0.0.1:8888" || DefaultMgmtAddress != "127.0.0.1:8088" {
		t.Fatalf("loopback defaults %q %q", DefaultProxyAddress, DefaultMgmtAddress)
	}
	if DefaultSessionMax != 64 {
		t.Fatalf("DefaultSessionMax=%d", DefaultSessionMax)
	}
	if DefaultStreamSlack != int64(64<<10) {
		t.Fatalf("DefaultStreamSlack=%d", DefaultStreamSlack)
	}
	if DefaultMaxInFlightBytes != int64(64<<20) || DefaultStoreMaxBytes != int64(256<<20) {
		t.Fatal("store/admission byte defaults")
	}
	if MaxDocumentBytes != 1<<20 || MaxRuleBodyReplace != int64(64<<10) {
		t.Fatal("document/rule caps")
	}
}

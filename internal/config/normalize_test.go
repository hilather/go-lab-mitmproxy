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

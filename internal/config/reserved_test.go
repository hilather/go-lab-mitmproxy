package config

import (
	"fmt"
	"testing"
)

func TestReservedKeysTable(t *testing.T) {
	keys := []string{
		"socks", "socks5", "socks4", "SOCKS5", "socks-proxy",
		"tproxy", "t-proxy", "transparent", "reverseproxy", "reverse_proxy",
		"publicca", "public-ca", "trustedroot", "trusted-root",
		"addon", "pythonaddon", "mitmproxyaddon", "mitmproxy", "mitmdump", "mitmweb",
		"exploit", "payloadgen", "attack", "sslstrip", "hstsstrip",
		"--socks", "SSL_STRIP",
	}
	for _, k := range keys {
		doc := fmt.Sprintf("apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  %s: true\n", k)
		t.Run(k, func(t *testing.T) {
			_, err := Decode([]byte(doc))
			_ = requireValidation(t, err, violationReservedName)
		})
	}
}

func TestNormalizeKey(t *testing.T) {
	cases := map[string]string{
		"--socks":       "socks",
		"socks_proxy":   "socksproxy",
		"SOCKS5":        "socks5",
		"reverse_proxy": "reverseproxy",
		"public-ca":     "publicca",
		"mitmProxy":     "mitmproxy",
		"SSL_STRIP":     "sslstrip",
	}
	for in, want := range cases {
		if got := normalizeKey(in); got != want {
			t.Fatalf("normalizeKey(%q)=%q want %q", in, got, want)
		}
	}
}

func TestReservedDoesNotApplyToHeaderSetOrLabels(t *testing.T) {
	t.Chdir(repoRoot(t))
	st, err := LoadFile(testdata(t, "valid", "rules-and-token.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	set := st.Spec.Rules.Items[0].Action.Headers.Set
	if set["X-Attack"] != "blocked" || set["Addon-Version"] != "1" {
		t.Fatalf("headers.set=%v", set)
	}
	if st.Metadata.Labels["addon-version"] != "test" {
		t.Fatalf("labels=%v", st.Metadata.Labels)
	}
}

func TestReservedDoesNotMatchLegitFields(t *testing.T) {
	if why := reservedReason(normalizeKey("maxFlows")); why != "" {
		t.Fatalf("maxFlows reserved: %s", why)
	}
	if why := reservedReason(normalizeKey("maxBodyBytes")); why != "" {
		t.Fatalf("maxBodyBytes reserved: %s", why)
	}
	if why := reservedReason(normalizeKey("insecureSkipVerify")); why != "" {
		t.Fatalf("insecureSkipVerify reserved: %s", why)
	}
	if why := reservedReason(normalizeKey("intercept")); why != "" {
		t.Fatalf("intercept reserved: %s", why)
	}
	if why := reservedReason(normalizeKey("acceptSOCKS5")); why != "" {
		t.Fatalf("acceptSOCKS5 reserved: %s", why)
	}
	if why := reservedReason(normalizeKey("originalDestination")); why != "" {
		t.Fatalf("originalDestination reserved: %s", why)
	}
	if why := reservedReason(normalizeKey("flowREST")); why != "" {
		t.Fatalf("flowREST reserved: %s", why)
	}
	if why := reservedReason(normalizeKey("mitmproxyREST")); why == "" {
		t.Fatal("mitmproxyREST must stay reserved")
	}
}

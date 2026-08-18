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
}

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// expectedInvalid is the fail-closed code each negative fixture must produce.
var expectedInvalid = map[string]string{
	"unknown-field.yaml":                          violationUnknownField,
	"unknown-field-nested.yaml":                   violationUnknownField,
	"missing-apiversion.yaml":                     violationRequired,
	"missing-kind.yaml":                           violationRequired,
	"bare-duration.yaml":                          violationInvalidValue,
	"bare-duration-zero.yaml":                     violationInvalidValue,
	"bare-bytes.yaml":                             violationInvalidValue,
	"reserved-socks.yaml":                         violationReservedName,
	"reserved-socks-bind.yaml":                    violationReservedName,
	"reserved-socks-userpass.yaml":                violationReservedName,
	"reserved-tproxy.yaml":                        violationReservedName,
	"reserved-publicca.yaml":                      violationReservedName,
	"reserved-mitmproxy.yaml":                     violationReservedName,
	"reserved-mitmproxy-rest.yaml":                violationReservedName,
	"accept-bind-without-socks.yaml":              violationInvalidValue,
	"accept-udp-without-socks5.yaml":              violationInvalidValue,
	"accept-userpass-without-users.yaml":          violationInvalidValue,
	"accept-userpass-without-socks5.yaml":         violationInvalidValue,
	"http2-origin-without-enabled.yaml":           violationInvalidValue,
	"http2-capture-push-without-origin.yaml":      violationInvalidValue,
	"http2-extended-connect-without-enabled.yaml": violationInvalidValue,
	"http2-grpc-decode-without-enabled.yaml":      violationInvalidValue,
	"hyphen-accept-bind.yaml":                     violationUnknownField,
	"protocols-http3.yaml":                        violationUnknownField,
	"protocols-unknown-nested.yaml":               violationUnknownField,
	"upstream-verify.yaml":                        violationUnknownField,
	"multi-doc.yaml":                              violationInvalidValue,
	"yaml-alias.yaml":                             violationInvalidValue,
	"duplicate-key.yaml":                          violationDuplicateKey,
	"rules-http-status.yaml":                      violationInvalidValue,
	"rules-hang-timeout-0.yaml":                   violationRequired,
	"rules-hang-timeout-31s.yaml":                 violationInvalidValue,
	"rules-hang-timeout-omitted.yaml":             violationRequired,
	"rules-redirect-empty-location.yaml":          violationRequired,
	"rules-redirect-crlf.yaml":                    violationInvalidValue,
	"rules-redirect-status-300.yaml":              violationInvalidValue,
	"rules-redirect-status-304.yaml":              violationInvalidValue,
	"rules-redirect-status-403.yaml":              violationInvalidValue,
	"rules-silent-close-reset.yaml":               violationInvalidValue,
	"rules-status-302.yaml":                       violationInvalidValue,
}

// TestConfigCompat is the positive+negative fixture matrix for make test-config-compat.
func TestConfigCompat(t *testing.T) {
	t.Chdir(repoRoot(t))
	validDir := testdata(t, "valid")
	ents, err := os.ReadDir(validDir)
	if err != nil {
		t.Fatal(err)
	}
	var validCount int
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		validCount++
		name := e.Name()
		t.Run("valid/"+name, func(t *testing.T) {
			st, err := LoadFile(filepath.Join(validDir, name))
			if err != nil {
				t.Fatal(err)
			}
			if st.APIVersion != model.APIVersionV1Alpha1 || st.Kind != model.KindLabMITM {
				t.Fatalf("api=%q kind=%q", st.APIVersion, st.Kind)
			}
			if name == "websocket-off.yaml" && st.Spec.Protocols.WebSocket.Enabled {
				t.Fatal("websocket-off.yaml must preserve protocols.websocket.enabled false")
			}
			rev, err := Revision(st)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := CanonicalJSON(st)
			if err != nil {
				t.Fatal(err)
			}
			again, err := Load(raw)
			if err != nil {
				t.Fatal(err)
			}
			rev2, err := Revision(again)
			if err != nil {
				t.Fatal(err)
			}
			if rev != rev2 {
				t.Fatalf("round-trip revision %s != %s", rev, rev2)
			}
			assertCanonicalMatchesSchema(t, raw)
		})
	}
	if validCount < 2 {
		t.Fatalf("expected at least defaults and explicit, got %d", validCount)
	}

	invalidDir := testdata(t, "invalid")
	ients, err := os.ReadDir(invalidDir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range ients {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := e.Name()
		want, ok := expectedInvalid[name]
		if !ok {
			t.Fatalf("no expectedInvalid code for %s (fail-closed: add it)", name)
		}
		seen[name] = true
		t.Run("invalid/"+name, func(t *testing.T) {
			_, err := LoadFile(filepath.Join(invalidDir, name))
			de := requireValidation(t, err, want)
			if de.Code != domainerr.CodeValidationFailed {
				t.Fatalf("code=%s", de.Code)
			}
		})
	}
	for name := range expectedInvalid {
		if !seen[name] {
			t.Fatalf("missing invalid fixture %s", name)
		}
	}
}

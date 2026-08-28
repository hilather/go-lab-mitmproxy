package config

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestRevisionStableAcrossFormatting(t *testing.T) {
	compact := `
apiVersion: labmitm.dev/v1alpha1
kind: LabMITM
metadata:
  name: lab-proxy
spec: {}
`
	spaced := strings.ReplaceAll(compact, "\n", "\n\n")
	spaced = "# header comment\n" + spaced
	a, err := Load([]byte(compact))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load([]byte(spaced))
	if err != nil {
		t.Fatal(err)
	}
	ra, err := Revision(a)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := Revision(b)
	if err != nil {
		t.Fatal(err)
	}
	if ra != rb {
		t.Fatalf("formatting changed revision\n%s\n%s", ra, rb)
	}
	if !strings.HasPrefix(string(ra), model.RevisionPrefix) {
		t.Fatalf("revision %q missing prefix", ra)
	}
	if len(ra) != len(model.RevisionPrefix)+64 {
		t.Fatalf("revision len=%d", len(ra))
	}
}

func TestRevisionChangesOnSilentRule(t *testing.T) {
	a, err := Load([]byte(mustLoad(t, "valid", "defaults.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	ra, err := Revision(a)
	if err != nil {
		t.Fatal(err)
	}
	if a.Spec.Rules.Enabled {
		t.Fatal("empty spec must keep rules.enabled false")
	}
	b, err := Load([]byte(mustLoad(t, "valid", "rules-silent-rst.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	rb, err := Revision(b)
	if err != nil {
		t.Fatal(err)
	}
	if ra == rb {
		t.Fatal("enabling a silent item must change runtimeRevision")
	}
	if !b.Spec.Rules.Enabled || b.Spec.Rules.Items[0].Action.Type != model.ActionSilent {
		t.Fatalf("silent fixture %+v", b.Spec.Rules)
	}
}

func TestRevisionChangesOnSemanticEdit(t *testing.T) {
	a, err := Load([]byte(mustLoad(t, "valid", "defaults.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	ra, err := Revision(a)
	if err != nil {
		t.Fatal(err)
	}
	a.Spec.Proxy.Hostname = "other.lab"
	rb, err := Revision(a)
	if err != nil {
		t.Fatal(err)
	}
	if ra == rb {
		t.Fatal("semantic edit did not change revision")
	}
}

func TestCanonicalEmptySpecGrowsProtocolGates(t *testing.T) {
	st, err := Load([]byte(mustLoad(t, "valid", "defaults.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CanonicalJSON(st)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	// Map keys are sorted; websocket carries inspectFrames beside enabled.
	want := []string{
		`"absoluteForm":{"enabled":true}`,
		`"connect":{"enabled":true}`,
		`"websocket":{"enabled":true,"inspectFrames":false}`,
		`"http2":{"capturePush":false,"clientCleartext":false,"enabled":false,"extendedConnect":false,"grpcDecode":false,"origin":false}`,
	}
	for _, frag := range want {
		if !strings.Contains(s, frag) {
			t.Fatalf("canonical JSON missing %s\n%s", frag, s)
		}
	}
}

func TestCanonicalJSONUsesIECAndDurationStrings(t *testing.T) {
	st, err := Load([]byte(mustLoad(t, "valid", "defaults.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CanonicalJSON(st)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, `"maxBytes":"256MiB"`) {
		t.Fatalf("missing IEC size: %s", s)
	}
	if !strings.Contains(s, `"sessionTimeout":"10m"`) {
		t.Fatalf("missing duration: %s", s)
	}
	if !strings.Contains(s, `"insecureSkipVerify":false`) {
		t.Fatalf("missing insecureSkipVerify: %s", s)
	}
	if strings.Contains(s, `"verify"`) {
		t.Fatalf("canonical JSON must not emit tls.upstream.verify: %s", s)
	}
}

func TestParseFormatByteSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		out  string
	}{
		{"10MiB", 10 << 20, "10MiB"},
		{"256KiB", 256 << 10, "256KiB"},
		{"1B", 1, "1B"},
		{"0B", 0, "0B"},
		{"1GiB", 1 << 30, "1GiB"},
	}
	for _, tc := range cases {
		got, err := ParseByteSize(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if int64(got) != tc.want {
			t.Fatalf("%s=%d want %d", tc.in, got, tc.want)
		}
		if FormatByteSize(int64(got)) != tc.out {
			t.Fatalf("format %d=%q want %q", got, FormatByteSize(int64(got)), tc.out)
		}
	}
	if _, err := ParseByteSize("10MB"); err == nil {
		t.Fatal("decimal MB must be rejected")
	}
	if _, err := ParseByteSize("10"); err == nil {
		t.Fatal("bare number must be rejected")
	}
}

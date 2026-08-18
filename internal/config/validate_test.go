package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestValidateDefaults(t *testing.T) {
	st, err := Load([]byte(mustLoad(t, "valid", "defaults.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(st); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCAFilesRequiresExisting(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: tls\nspec:\n  tls:\n    ca:\n      mode: files\n      certFile: /no/such/cert.pem\n      keyFile: /no/such/key.pem\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationUnresolved)
}

func TestValidateCAFilesResolves(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: tls\nspec:\n  tls:\n    ca:\n      mode: files\n      certFile: " + cert + "\n      keyFile: " + key + "\n"
	st, err := Load([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.TLS.CA.Mode != model.CAModeFiles {
		t.Fatalf("mode=%q", st.Spec.TLS.CA.Mode)
	}
}

func TestValidateGenerateRejectsUnusedKeyFiles(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: tls\nspec:\n  tls:\n    ca:\n      mode: generate\n      certFile: /tmp/x.pem\n      keyFile: /tmp/y.pem\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestValidateEmptyKeyPEM(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: tls\nspec:\n  tls:\n    ca:\n      mode: files\n      certFile: " + cert + "\n      keyFile: " + key + "\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestValidateWorldWritableKey(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0o666); err != nil {
		t.Fatal(err)
	}
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: tls\nspec:\n  tls:\n    ca:\n      mode: files\n      certFile: " + cert + "\n      keyFile: " + key + "\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestValidateMissingAPIVersion(t *testing.T) {
	_, err := Load([]byte(mustLoad(t, "invalid", "missing-apiversion.yaml")))
	_ = requireValidation(t, err, violationRequired)
}

func TestValidateNil(t *testing.T) {
	_ = requireValidation(t, Validate(nil), violationRequired)
}

func TestValidateShortTokenSecret(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("tooshort\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec:\n  management:\n    auth:\n      mode: bearer\n      tokens:\n        - id: admin\n          secretFile: " + tok + "\n          role: administrator\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestValidateStoreCaps(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: s\nspec:\n  store:\n    maxBytes: 512KiB\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestValidateDuplicateRuleID(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: r\nspec:\n  rules:\n    items:\n      - id: same\n        action:\n          type: drop\n      - id: same\n        action:\n          type: drop\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationDuplicateID)
}

func TestValidateUpstreamVerifyFixture(t *testing.T) {
	_, err := Load([]byte(mustLoad(t, "invalid", "upstream-verify.yaml")))
	de := requireValidation(t, err, violationUnknownField)
	found := false
	for _, v := range de.FieldViolations {
		if v.Path == "spec.tls.upstream.verify" || v.Path == "verify" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want verify path in %+v", de.FieldViolations)
	}
}

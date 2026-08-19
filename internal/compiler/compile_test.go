package compiler

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestCompileNilState(t *testing.T) {
	_, err := Compile(context.Background(), nil, CompileOpts{})
	if err == nil {
		t.Fatal("nil state compiled")
	}
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeValidationFailed {
		t.Fatalf("err=%v, want validation_failed", err)
	}
}

func TestCompileCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Compile(ctx, &model.State{}, CompileOpts{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
}

func TestCompileDefaultsRevisionAndCA(t *testing.T) {
	st := loadDefaults(t)
	clk := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	res, err := Compile(context.Background(), st, CompileOpts{Now: clk, Generation: 0})
	if err != nil {
		t.Fatal(err)
	}
	if res.Canonical == st {
		t.Fatal("Compile must not retain the caller pointer")
	}
	wantRev, err := config.Revision(st)
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != wantRev || res.BootstrapRevision != wantRev {
		t.Fatalf("revision=%s bootstrap=%s want %s", res.Revision, res.BootstrapRevision, wantRev)
	}
	if res.CompiledAt != clk {
		t.Fatalf("CompiledAt=%s", res.CompiledAt)
	}
	if res.Canonical.Spec.Listeners.Proxy.Address != config.DefaultProxyAddress {
		t.Fatalf("proxy listen %q", res.Canonical.Spec.Listeners.Proxy.Address)
	}
	if res.Rules == nil {
		t.Fatal("missing rules engine")
	}
	if res.CA == nil {
		t.Fatal("compile must mint a generate-mode CA even when intercept is off")
	}
	ca := res.CA.Status()
	if ca.Mode != model.CAModeGenerate || ca.SPKISHA256 == "" {
		t.Fatalf("CA status %+v", ca)
	}
}

func TestCompileDeterministicForSameCanonicalJSON(t *testing.T) {
	st := loadDefaults(t)
	clk := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	a, err := Compile(context.Background(), st, CompileOpts{Now: clk})
	if err != nil {
		t.Fatal(err)
	}
	st2 := loadDefaults(t)
	b, err := Compile(context.Background(), st2, CompileOpts{Now: clk})
	if err != nil {
		t.Fatal(err)
	}
	if a.Revision != b.Revision {
		t.Fatalf("revision drifted\n%s\n%s", a.Revision, b.Revision)
	}
	ja, err := config.CanonicalJSON(a.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	jb, err := config.CanonicalJSON(b.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ja, jb) {
		t.Fatal("canonical JSON differed")
	}
}

func TestCompileDoesNotMutateInput(t *testing.T) {
	st := loadDefaults(t)
	before := st.Spec.Proxy.Hostname
	res, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	st.Spec.Proxy.Hostname = "mutated"
	if res.Canonical.Spec.Proxy.Hostname == "mutated" {
		t.Fatal("Compile mutated caller state into Canonical")
	}
	if before != "" && res.Canonical.Spec.Proxy.Hostname != before && res.Canonical.Spec.Proxy.Hostname != config.DefaultProxyHostname {
		// defaults materialize hostname; just ensure we did not take the mutation
		t.Fatalf("hostname=%q", res.Canonical.Spec.Proxy.Hostname)
	}
}

func TestCompileInvalidRejected(t *testing.T) {
	st := &model.State{
		APIVersion: model.APIVersionV1Alpha1,
		Kind:       model.KindLabMITM,
		Metadata:   model.Metadata{Name: "bad"},
		Spec: model.Spec{
			TLS: model.TLSSpec{CA: model.CASpec{Mode: "public"}},
		},
	}
	_, err := Compile(context.Background(), st, CompileOpts{})
	if err == nil {
		t.Fatal("public CA compiled")
	}
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeValidationFailed {
		t.Fatalf("err=%v", err)
	}
}

func TestCompileReusesCAWhenTLSUnchanged(t *testing.T) {
	st := loadDefaults(t)
	first, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	copied := loadDefaults(t)
	copied.Spec.Rules.Enabled = true
	second, err := Compile(context.Background(), copied, CompileOpts{Previous: first})
	if err != nil {
		t.Fatal(err)
	}
	if first.CA != second.CA {
		t.Fatal("replaceRules-shaped compile must reuse the CA handle")
	}
	if first.CA.Status().SPKISHA256 != second.CA.Status().SPKISHA256 {
		t.Fatal("SPKI changed on reuse")
	}
}

func TestCompileReplaceTLSRotatesGenerateCA(t *testing.T) {
	st := loadDefaults(t)
	first, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	copied := loadDefaults(t)
	copied.Spec.TLS.Intercept = true
	second, err := Compile(context.Background(), copied, CompileOpts{Previous: first})
	if err != nil {
		t.Fatal(err)
	}
	if first.CA == second.CA {
		t.Fatal("replaceTLS must recompile the CA handle")
	}
	if first.CA.Status().SPKISHA256 == second.CA.Status().SPKISHA256 {
		t.Fatal("generate-mode replaceTLS must rotate the CA")
	}
}

func TestCompileRotateCA(t *testing.T) {
	st := loadDefaults(t)
	first, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(context.Background(), loadDefaults(t), CompileOpts{Previous: first, RotateCA: true})
	if err != nil {
		t.Fatal(err)
	}
	if first.CA.Status().SPKISHA256 == second.CA.Status().SPKISHA256 {
		t.Fatal("RotateCA must mint a new generate-mode CA")
	}
}

func TestCompileFilesCA(t *testing.T) {
	root := repoRoot(t)
	st := loadDefaults(t)
	st.Spec.TLS.CA.Mode = model.CAModeFiles
	st.Spec.TLS.CA.CertFile = filepath.Join(root, "testdata", "tls", "ca.pem")
	st.Spec.TLS.CA.KeyFile = filepath.Join(root, "testdata", "tls", "ca-key.pem")
	res, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if res.CA.Status().Mode != model.CAModeFiles {
		t.Fatalf("mode=%s", res.CA.Status().Mode)
	}
	pem := res.CA.CertPEM()
	if !bytes.Contains(pem, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("cert PEM=%s", pem)
	}
	if bytes.Contains(pem, []byte("PRIVATE")) {
		t.Fatal("CertPEM leaked a private key")
	}
}

func loadDefaults(t *testing.T) *model.State {
	t.Helper()
	root := repoRoot(t)
	st, err := config.LoadFile(filepath.Join(root, "testdata", "config", "valid", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

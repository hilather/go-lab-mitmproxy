package compiler

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
)

func userPassState(t *testing.T, username, password string) (*model.State, string, string) {
	t.Helper()
	dir := t.TempDir()
	uf := filepath.Join(dir, "user")
	pf := filepath.Join(dir, "pass")
	if err := os.WriteFile(uf, []byte(username+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pf, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := loadDefaults(t)
	st.Spec.Listeners.Proxy.AcceptSOCKS5 = true
	st.Spec.Listeners.Proxy.AcceptUserPass = true
	st.Spec.Listeners.Proxy.UserPass.Users = []model.UserPassUserSpec{{
		ID:           "lab-socks",
		UsernameFile: uf,
		PasswordFile: pf,
	}}
	return st, uf, pf
}

func TestCompileLoadsSOCKSUsersOnStart(t *testing.T) {
	st, _, _ := userPassState(t, "labuser", "labpass12")
	snap, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.SOCKSUsers) != 1 || snap.SOCKSUsers[0].ID != "lab-socks" {
		t.Fatalf("SOCKSUsers=%+v", snap.SOCKSUsers)
	}
	want := snapshot.DigestSOCKSUser([]byte("labuser"), []byte("labpass12"))
	if snap.SOCKSUsers[0].Digest != want {
		t.Fatalf("digest=%x want %x", snap.SOCKSUsers[0].Digest, want)
	}
}

func TestCompileSOCKSUsersEmptyWhenFlagOff(t *testing.T) {
	st := loadDefaults(t)
	snap, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.SOCKSUsers) != 0 {
		t.Fatalf("SOCKSUsers=%+v", snap.SOCKSUsers)
	}
}

func TestCompileSOCKSUsersCopiedOnLiveApply(t *testing.T) {
	st, _, pf := userPassState(t, "labuser", "labpass12")
	first, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pf, []byte("newpassword1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	copied := loadDefaults(t)
	copied.Spec.Listeners.Proxy = first.Canonical.Spec.Listeners.Proxy
	copied.Spec.Rules.Enabled = true
	second, err := Compile(context.Background(), copied, CompileOpts{Previous: first})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.SOCKSUsers) != 1 {
		t.Fatalf("SOCKSUsers=%+v", second.SOCKSUsers)
	}
	if second.SOCKSUsers[0].Digest != first.SOCKSUsers[0].Digest {
		t.Fatal("replaceRules-shaped compile must not reload SOCKS password files")
	}
	fresh, err := Compile(context.Background(), copied, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.SOCKSUsers[0].Digest == first.SOCKSUsers[0].Digest {
		t.Fatal("Start/Reset compile must load current file bytes")
	}
}

func TestCompileSOCKSUsersCopiedWhenPasswordFileVanishes(t *testing.T) {
	st, uf, pf := userPassState(t, "labuser", "labpass12")
	first, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(uf); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pf); err != nil {
		t.Fatal(err)
	}
	copied := loadDefaults(t)
	copied.Spec.Listeners.Proxy = first.Canonical.Spec.Listeners.Proxy
	copied.Spec.Rules.Enabled = true
	second, err := Compile(context.Background(), copied, CompileOpts{Previous: first})
	if err != nil {
		t.Fatal(err)
	}
	if second.SOCKSUsers[0].Digest != first.SOCKSUsers[0].Digest {
		t.Fatal("vanished password file must not fail live Compile")
	}
	_, err = Compile(context.Background(), copied, CompileOpts{})
	if err == nil {
		t.Fatal("Start/Reset must fail closed when SOCKS files are missing")
	}
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeValidationFailed {
		t.Fatalf("err=%v", err)
	}
}

func TestCompileSOCKSUsersCopiedOnReplaceTLS(t *testing.T) {
	st, _, pf := userPassState(t, "labuser", "labpass12")
	first, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pf, []byte("rotatedpass1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	copied := loadDefaults(t)
	copied.Spec.Listeners.Proxy = first.Canonical.Spec.Listeners.Proxy
	copied.Spec.TLS.Intercept = true
	second, err := Compile(context.Background(), copied, CompileOpts{Previous: first})
	if err != nil {
		t.Fatal(err)
	}
	if first.CA == second.CA {
		t.Fatal("replaceTLS must recompile the CA handle")
	}
	if second.SOCKSUsers[0].Digest != first.SOCKSUsers[0].Digest {
		t.Fatal("SOCKSUsers must not key reload off tlsUnchanged")
	}
}

func TestCompileSOCKSUsersNotInCanonicalOrExport(t *testing.T) {
	st, _, _ := userPassState(t, "labuser", "labpass12")
	snap, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := config.CanonicalJSON(snap.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	yaml, err := config.CanonicalYAML(snap.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	digest := hex.EncodeToString(snap.SOCKSUsers[0].Digest[:])
	for _, blob := range [][]byte{raw, yaml} {
		s := string(blob)
		if strings.Contains(s, "labpass12") || strings.Contains(s, "labuser") {
			t.Fatalf("canonical leaked SOCKS secret: %s", s)
		}
		if strings.Contains(s, digest) {
			t.Fatalf("canonical leaked SOCKS digest: %s", s)
		}
		if bytes.Contains(blob, snap.SOCKSUsers[0].Digest[:]) {
			t.Fatal("canonical contained raw digest bytes")
		}
	}
}

func TestCompileStartFailsWhenUserPassFileMissing(t *testing.T) {
	st, uf, _ := userPassState(t, "labuser", "labpass12")
	if err := os.Remove(uf); err != nil {
		t.Fatal(err)
	}
	_, err := Compile(context.Background(), st, CompileOpts{})
	if err == nil {
		t.Fatal("missing username file compiled")
	}
}

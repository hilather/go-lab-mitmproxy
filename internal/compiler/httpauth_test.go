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
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
)

func httpAuthState(t *testing.T, username, password string) (*model.State, string, string) {
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
	st.Spec.Proxy.HTTPAuth = model.HTTPAuthSpec{
		Enabled: true,
		Realm:   config.DefaultHTTPAuthRealm,
		Users: []model.UserPassUserSpec{{
			ID:           "lab-proxy",
			UsernameFile: uf,
			PasswordFile: pf,
		}},
	}
	return st, uf, pf
}

func TestCompileLoadsHTTPAuthUsersOnStart(t *testing.T) {
	st, _, _ := httpAuthState(t, "labuser", "labpass12")
	snap, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.HTTPAuthUsers) != 1 || snap.HTTPAuthUsers[0].ID != "lab-proxy" {
		t.Fatalf("HTTPAuthUsers=%+v", snap.HTTPAuthUsers)
	}
	want := snapshot.DigestSOCKSUser([]byte("labuser"), []byte("labpass12"))
	if snap.HTTPAuthUsers[0].Digest != want {
		t.Fatalf("digest=%x want %x", snap.HTTPAuthUsers[0].Digest, want)
	}
}

func TestCompileHTTPAuthUsersEmptyWhenDisabled(t *testing.T) {
	st, _, _ := httpAuthState(t, "labuser", "labpass12")
	st.Spec.Proxy.HTTPAuth.Enabled = false
	snap, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.HTTPAuthUsers) != 0 {
		t.Fatalf("HTTPAuthUsers=%+v", snap.HTTPAuthUsers)
	}
}

func TestCompileHTTPAuthUsersCopiedOnLiveApply(t *testing.T) {
	st, _, pf := httpAuthState(t, "labuser", "labpass12")
	first, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pf, []byte("newpassword1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	copied := loadDefaults(t)
	copied.Spec.Proxy.HTTPAuth = first.Canonical.Spec.Proxy.HTTPAuth
	copied.Spec.Rules.Enabled = true
	second, err := Compile(context.Background(), copied, CompileOpts{Previous: first})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.HTTPAuthUsers) != 1 {
		t.Fatalf("HTTPAuthUsers=%+v", second.HTTPAuthUsers)
	}
	if second.HTTPAuthUsers[0].Digest != first.HTTPAuthUsers[0].Digest {
		t.Fatal("replaceRules-shaped compile must not reload HTTP auth files")
	}
	fresh, err := Compile(context.Background(), copied, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.HTTPAuthUsers[0].Digest == first.HTTPAuthUsers[0].Digest {
		t.Fatal("Start/Reset compile must load current file bytes")
	}
}

func TestCompileHTTPAuthReloadDoesNotKeepStaleDigests(t *testing.T) {
	st, _, pf := httpAuthState(t, "labuser", "labpass12")
	first, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pf, []byte("rotatedpass1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	copied := loadDefaults(t)
	copied.Spec.Proxy.HTTPAuth = first.Canonical.Spec.Proxy.HTTPAuth
	second, err := Compile(context.Background(), copied, CompileOpts{Previous: first, ReloadHTTPAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	if second.HTTPAuthUsers[0].Digest == first.HTTPAuthUsers[0].Digest {
		t.Fatal("replaceHTTPAuth must restat files and not keep stale digests")
	}
	want := snapshot.DigestSOCKSUser([]byte("labuser"), []byte("rotatedpass1"))
	if second.HTTPAuthUsers[0].Digest != want {
		t.Fatalf("digest=%x want %x", second.HTTPAuthUsers[0].Digest, want)
	}
}

func TestCompileHTTPAuthVanishedFileFailsReplaceOnly(t *testing.T) {
	st, uf, pf := httpAuthState(t, "labuser", "labpass12")
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
	copied.Spec.Proxy.HTTPAuth = first.Canonical.Spec.Proxy.HTTPAuth
	copied.Spec.Rules.Enabled = true
	second, err := Compile(context.Background(), copied, CompileOpts{Previous: first})
	if err != nil {
		t.Fatal(err)
	}
	if second.HTTPAuthUsers[0].Digest != first.HTTPAuthUsers[0].Digest {
		t.Fatal("vanished HTTP auth file must not fail replaceRules-shaped compile")
	}
	_, err = Compile(context.Background(), copied, CompileOpts{Previous: first, ReloadHTTPAuth: true})
	if err == nil {
		t.Fatal("replaceHTTPAuth must fail when files vanished")
	}
	_, err = Compile(context.Background(), copied, CompileOpts{})
	if err == nil {
		t.Fatal("Start/Reset must fail closed when HTTP auth files are missing")
	}
}

func TestCompileHTTPAuthRevisionUsesPathsNotDigests(t *testing.T) {
	st, _, pf := httpAuthState(t, "labuser", "labpass12")
	first, err := Compile(context.Background(), st, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	r1, err := config.Revision(first.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pf, []byte("otherpass99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := Compile(context.Background(), first.Canonical, CompileOpts{})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := config.Revision(second.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	if r1 != r2 {
		t.Fatal("revision must hash file paths, not digest bytes")
	}
	if second.HTTPAuthUsers[0].Digest == first.HTTPAuthUsers[0].Digest {
		t.Fatal("Start compile must pick up new file bytes")
	}
}

func TestCompileHTTPAuthUsersNotInCanonicalOrExport(t *testing.T) {
	st, _, _ := httpAuthState(t, "labuser", "labpass12")
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
	digest := hex.EncodeToString(snap.HTTPAuthUsers[0].Digest[:])
	for _, blob := range [][]byte{raw, yaml} {
		s := string(blob)
		if strings.Contains(s, "labpass12") || strings.Contains(s, "labuser") {
			t.Fatalf("canonical leaked HTTP auth secret: %s", s)
		}
		if strings.Contains(s, digest) {
			t.Fatalf("canonical leaked HTTP auth digest: %s", s)
		}
		if bytes.Contains(blob, snap.HTTPAuthUsers[0].Digest[:]) {
			t.Fatal("canonical contained raw digest bytes")
		}
	}
}

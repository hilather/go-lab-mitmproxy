package compiler

import (
	"strconv"
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
)

func compileHTTPAuthUsers(spec model.Spec, opts CompileOpts) ([]snapshot.SOCKSUserDigest, error) {
	if opts.Previous != nil && !opts.ReloadHTTPAuth {
		return append([]snapshot.SOCKSUserDigest(nil), opts.Previous.HTTPAuthUsers...), nil
	}
	return loadHTTPAuthUserFiles(spec)
}

func loadHTTPAuthUserFiles(spec model.Spec) ([]snapshot.SOCKSUserDigest, error) {
	if !spec.Proxy.HTTPAuth.Enabled {
		return nil, nil
	}
	users := spec.Proxy.HTTPAuth.Users
	out := make([]snapshot.SOCKSUserDigest, 0, len(users))
	seen := map[[32]byte]string{}
	for i, u := range users {
		base := "spec.proxy.httpAuth.users[" + strconv.Itoa(i) + "]"
		user, err := readRFC1929File(u.UsernameFile)
		if err != nil {
			return nil, domainerr.ValidationFailed("HTTP auth username file is unavailable",
				domainerr.FieldViolation{Path: base + ".usernameFile", Code: "unresolved_reference", Message: "file does not resolve at load"})
		}
		pass, err := readRFC1929File(u.PasswordFile)
		if err != nil {
			zeroSecret(user)
			return nil, domainerr.ValidationFailed("HTTP auth password file is unavailable",
				domainerr.FieldViolation{Path: base + ".passwordFile", Code: "unresolved_reference", Message: "file does not resolve at load"})
		}
		if len(user) < minSOCKSSecret || len(user) > maxSOCKSSecret {
			zeroSecret(user)
			zeroSecret(pass)
			return nil, domainerr.ValidationFailed("HTTP auth username length is invalid",
				domainerr.FieldViolation{Path: base + ".usernameFile", Code: "invalid_value", Message: "username must be 1–255 bytes"})
		}
		if len(pass) < minSOCKSSecret || len(pass) > maxSOCKSSecret {
			zeroSecret(user)
			zeroSecret(pass)
			return nil, domainerr.ValidationFailed("HTTP auth password length is invalid",
				domainerr.FieldViolation{Path: base + ".passwordFile", Code: "invalid_value", Message: "password must be 1–255 bytes"})
		}
		d := snapshot.DigestSOCKSUser(user, pass)
		zeroSecret(user)
		zeroSecret(pass)
		id := strings.TrimSpace(u.ID)
		if prev, ok := seen[d]; ok {
			return nil, domainerr.ValidationFailed("duplicate HTTP auth user credentials",
				domainerr.FieldViolation{Path: base, Code: "duplicate_id", Message: "HTTP auth user credentials match " + prev})
		}
		seen[d] = id
		out = append(out, snapshot.SOCKSUserDigest{ID: id, Digest: d})
	}
	return out, nil
}

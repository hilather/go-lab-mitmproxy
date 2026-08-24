package compiler

import (
	"os"
	"strconv"
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
)

const (
	minSOCKSSecret = 1
	maxSOCKSSecret = 255
)

func compileSOCKSUsers(spec model.Spec, opts CompileOpts) ([]snapshot.SOCKSUserDigest, error) {
	if opts.Previous != nil {
		return append([]snapshot.SOCKSUserDigest(nil), opts.Previous.SOCKSUsers...), nil
	}
	return loadSOCKSUserFiles(spec)
}

func loadSOCKSUserFiles(spec model.Spec) ([]snapshot.SOCKSUserDigest, error) {
	if !spec.Listeners.Proxy.AcceptUserPass {
		return nil, nil
	}
	users := spec.Listeners.Proxy.UserPass.Users
	out := make([]snapshot.SOCKSUserDigest, 0, len(users))
	for i, u := range users {
		base := "spec.listeners.proxy.userPass.users[" + strconv.Itoa(i) + "]"
		user, err := readRFC1929File(u.UsernameFile)
		if err != nil {
			return nil, domainerr.ValidationFailed("SOCKS username file is unavailable",
				domainerr.FieldViolation{Path: base + ".usernameFile", Code: "unresolved_reference", Message: "file does not resolve at load"})
		}
		pass, err := readRFC1929File(u.PasswordFile)
		if err != nil {
			zeroSecret(user)
			return nil, domainerr.ValidationFailed("SOCKS password file is unavailable",
				domainerr.FieldViolation{Path: base + ".passwordFile", Code: "unresolved_reference", Message: "file does not resolve at load"})
		}
		if len(user) < minSOCKSSecret || len(user) > maxSOCKSSecret {
			zeroSecret(user)
			zeroSecret(pass)
			return nil, domainerr.ValidationFailed("SOCKS username length is invalid",
				domainerr.FieldViolation{Path: base + ".usernameFile", Code: "invalid_value", Message: "username must be 1–255 bytes"})
		}
		if len(pass) < minSOCKSSecret || len(pass) > maxSOCKSSecret {
			zeroSecret(user)
			zeroSecret(pass)
			return nil, domainerr.ValidationFailed("SOCKS password length is invalid",
				domainerr.FieldViolation{Path: base + ".passwordFile", Code: "invalid_value", Message: "password must be 1–255 bytes"})
		}
		d := snapshot.DigestSOCKSUser(user, pass)
		zeroSecret(user)
		zeroSecret(pass)
		out = append(out, snapshot.SOCKSUserDigest{ID: strings.TrimSpace(u.ID), Digest: d})
	}
	return out, nil
}

func readRFC1929File(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return []byte(line), nil
	}
	return nil, os.ErrInvalid
}

func zeroSecret(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

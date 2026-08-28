package compiler

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/rules"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
	"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm"
)

// CompileOpts controls revision metadata, the compile clock, and CA reuse.
type CompileOpts struct {
	Now               time.Time
	BootstrapRevision model.Revision
	Generation        model.Generation
	// Previous, when set, lets Compile reuse the CA handle if the TLS spec
	// is unchanged and copy SOCKSUsers without rereading password files.
	// Reset leaves this nil so generate-mode rotates and SOCKS files reload.
	Previous *snapshot.Snapshot
	// RotateCA forces a new generate-mode CA (and a files-mode reload).
	RotateCA bool
	// ReloadHTTPAuth restats spec.proxy.httpAuth user files (D76). Set when
	// Previous is nil (Start/Reset) or the live ops include replaceHTTPAuth.
	ReloadHTTPAuth bool
}

// Compile normalizes and validates st (copy-on-write), hashes canonical JSON,
// compiles the rules engine, generates or loads the lab CA, and compiles the
// SOCKS user-pass digest table (copy Previous.SOCKSUsers when Previous != nil).
func Compile(ctx context.Context, st *model.State, opts CompileOpts) (*snapshot.Snapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n, err := config.Normalize(st)
	if err != nil {
		return nil, err
	}
	if err := validateForCompile(n, opts); err != nil {
		return nil, err
	}
	rev, err := config.Revision(n)
	if err != nil {
		return nil, err
	}
	bootRev := opts.BootstrapRevision
	if bootRev == "" {
		bootRev = rev
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ca, err := compileCA(n.Spec.TLS, opts)
	if err != nil {
		return nil, err
	}
	socksUsers, err := compileSOCKSUsers(n.Spec, opts)
	if err != nil {
		return nil, err
	}
	httpAuthUsers, err := compileHTTPAuthUsers(n.Spec, opts)
	if err != nil {
		return nil, err
	}
	return &snapshot.Snapshot{
		Canonical:         n,
		Revision:          rev,
		BootstrapRevision: bootRev,
		Generation:        opts.Generation,
		CompiledAt:        now,
		Rules:             rules.New(n.Spec.Rules),
		CA:                ca,
		SOCKSUsers:        socksUsers,
		HTTPAuthUsers:     httpAuthUsers,
	}, nil
}

func validateForCompile(n *model.State, opts CompileOpts) error {
	if opts.Previous != nil {
		return config.ValidateLiveApplyOpts(n, config.LiveApplyOpts{
			SkipHTTPAuthFiles: !opts.ReloadHTTPAuth,
		})
	}
	return config.Validate(n)
}

func compileCA(spec model.TLSSpec, opts CompileOpts) (*tlsmitm.Authority, error) {
	prev := opts.Previous
	if !opts.RotateCA && prev != nil && prev.CA != nil && tlsUnchanged(prev, spec) {
		return prev.CA, nil
	}
	auth, err := tlsmitm.New(tlsmitm.Options{
		Mode:               spec.CA.Mode,
		CertFile:           spec.CA.CertFile,
		KeyFile:            spec.CA.KeyFile,
		InsecureSkipVerify: spec.Upstream.InsecureSkipVerify,
		ExtraCAFiles:       spec.Upstream.ExtraCAFiles,
	})
	if err != nil {
		return nil, domainerr.ValidationFailed("compile lab CA: "+err.Error(),
			domainerr.FieldViolation{Path: "spec.tls.ca", Code: "invalid_value", Message: err.Error()})
	}
	return auth, nil
}

func tlsUnchanged(prev *snapshot.Snapshot, next model.TLSSpec) bool {
	if prev == nil || prev.Canonical == nil {
		return false
	}
	return tlsSpecEqual(prev.Canonical.Spec.TLS, next)
}

func tlsSpecEqual(a, b model.TLSSpec) bool {
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(left, right)
}

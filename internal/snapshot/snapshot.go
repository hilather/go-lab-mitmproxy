package snapshot

import (
	"crypto/sha256"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/rules"
	"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm"
)

// Snapshot is immutable after compiler.Compile returns. Flow contents are not a field.
// Rules and CA are compiled handles so live apply can swap a new pointer while
// in-flight sessions keep the one they loaded.
type Snapshot struct {
	Canonical         *model.State
	Revision          model.Revision
	BootstrapRevision model.Revision
	Generation        model.Generation
	CompiledAt        time.Time
	// Rules is the compiled first-match engine (never nil after Compile).
	Rules *rules.Engine
	// CA is the compiled lab CA handle. Generate-mode material is not in Canonical.
	CA *tlsmitm.Authority
	// SOCKSUsers is the RFC 1929 digest table (D60). Reset-only; empty when
	// acceptUserPass is false. Never Canonical, never GET /v1/state / export.
	SOCKSUsers []SOCKSUserDigest
}

// SOCKSUserDigest is one compiled SOCKS5 username/password principal.
// Digest is SHA-256(uint8(len(username)) || username || uint8(len(password)) || password).
type SOCKSUserDigest struct {
	ID     string
	Digest [sha256.Size]byte
}

// DigestSOCKSUser hashes RFC 1929 credentials. Callers must pass 1–255 byte
// username and password; the length prefix is a single uint8.
func DigestSOCKSUser(username, password []byte) [sha256.Size]byte {
	n := 2 + len(username) + len(password)
	buf := make([]byte, n)
	buf[0] = byte(len(username))
	copy(buf[1:], username)
	buf[1+len(username)] = byte(len(password))
	copy(buf[2+len(username):], password)
	sum := sha256.Sum256(buf)
	for i := range buf {
		buf[i] = 0
	}
	return sum
}

// Drifted reports runtimeRevision != bootstrapRevision.
func (s *Snapshot) Drifted() bool {
	if s == nil {
		return false
	}
	return s.Revision != s.BootstrapRevision
}

// Spec is the compiled desired state, or a zero spec.
func (s *Snapshot) Spec() model.Spec {
	if s == nil || s.Canonical == nil {
		return model.Spec{}
	}
	return s.Canonical.Spec
}

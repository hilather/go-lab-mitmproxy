package snapshot

import (
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

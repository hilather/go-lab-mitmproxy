package observability

// Warning codes are a bounded, stable Status DTO surface.
const (
	WarnProxyUnbound    = "proxy_unbound"
	WarnStoreDown       = "store_down"
	WarnMgmtUnbound     = "management_unbound"
	WarnListenerUnbound = "listener_unbound"
	WarnCAMissing       = "ca_not_compiled"
	WarnOrigDestUnbound = "origdest_unbound"
)

// MaxWarnings caps the Status warning list.
const MaxWarnings = 16

// Warning is one agent-readable operational note.
type Warning struct {
	Code    string
	Message string
}

// Facts are process observations used to evaluate health.
type Facts struct {
	ProcessDown bool
	ProxyBound  bool
	StoreUp     bool
	// MgmtBound is true when the management listener is accepting.
	MgmtBound bool
	// MgmtOff is true when management was explicitly disabled (off/none/-).
	MgmtOff bool
	// CAReady is true when intercept is off, or the compiled snapshot has a CA.
	CAReady bool
	// OrigDestBound is true when the original-destination listener is accepting.
	OrigDestBound bool
	// OrigDestOff is true when originalDestination.enabled is false (1.0 default).
	OrigDestOff bool
}

// Probe is liveness and readiness plus bounded warnings.
type Probe struct {
	Live     bool
	Ready    bool
	Warnings []Warning
}

// Evaluate implements pack 11 health semantics:
//   - Live: process is serving (not ProcessDown).
//   - Ready: live, proxy bound, store initialized, management bound or
//     explicitly off, orig-dest bound or off (D56), and CA compiled when
//     intercept is on. Ready does not require MCP clients, a non-empty
//     store, or successful upstreams.
func Evaluate(in Facts) Probe {
	p := Probe{Live: !in.ProcessDown}
	mgmtOK := in.MgmtBound || in.MgmtOff
	origdestOK := in.OrigDestBound || in.OrigDestOff
	p.Ready = p.Live && in.ProxyBound && in.StoreUp && mgmtOK && origdestOK && in.CAReady

	add := func(code, msg string) {
		if len(p.Warnings) >= MaxWarnings {
			return
		}
		p.Warnings = append(p.Warnings, Warning{Code: code, Message: msg})
	}
	if !in.ProxyBound {
		add(WarnProxyUnbound, "proxy listener is not bound")
		add(WarnListenerUnbound, "a required listener is not bound")
	}
	if !in.StoreUp {
		add(WarnStoreDown, "flow store is not initialized")
	}
	if !mgmtOK {
		add(WarnMgmtUnbound, "management listener is not bound")
		if in.ProxyBound {
			add(WarnListenerUnbound, "a required listener is not bound")
		}
	}
	if !origdestOK {
		add(WarnOrigDestUnbound, "original-destination listener is not bound")
		if in.ProxyBound && mgmtOK {
			add(WarnListenerUnbound, "a required listener is not bound")
		}
	}
	if !in.CAReady {
		add(WarnCAMissing, "lab CA is not compiled while tls.intercept is true")
	}
	return p
}

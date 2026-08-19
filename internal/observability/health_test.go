package observability

import "testing"

func TestEvaluateReadyRequiresProxyStoreAndCA(t *testing.T) {
	ready := Evaluate(Facts{ProxyBound: true, StoreUp: true, MgmtBound: true, CAReady: true, OrigDestOff: true})
	if !ready.Live || !ready.Ready {
		t.Fatalf("healthy probe=%+v", ready)
	}

	down := Evaluate(Facts{ProcessDown: true, ProxyBound: true, StoreUp: true, MgmtBound: true, CAReady: true, OrigDestOff: true})
	if down.Live || down.Ready {
		t.Fatalf("process down still live/ready: %+v", down)
	}

	noProxy := Evaluate(Facts{StoreUp: true, MgmtBound: true, CAReady: true, OrigDestOff: true})
	if noProxy.Ready {
		t.Fatal("missing proxy must be unready")
	}
	if !hasCode(noProxy.Warnings, WarnProxyUnbound) {
		t.Fatalf("warnings=%v", noProxy.Warnings)
	}

	noStore := Evaluate(Facts{ProxyBound: true, MgmtBound: true, CAReady: true, OrigDestOff: true})
	if noStore.Ready || !hasCode(noStore.Warnings, WarnStoreDown) {
		t.Fatalf("missing store=%+v", noStore)
	}

	mgmtOff := Evaluate(Facts{ProxyBound: true, StoreUp: true, MgmtOff: true, CAReady: true, OrigDestOff: true})
	if !mgmtOff.Ready {
		t.Fatalf("explicitly-off management must still be ready: %+v", mgmtOff)
	}

	mgmtMissing := Evaluate(Facts{ProxyBound: true, StoreUp: true, CAReady: true, OrigDestOff: true})
	if mgmtMissing.Ready {
		t.Fatal("management neither bound nor off must be unready")
	}

	noCA := Evaluate(Facts{ProxyBound: true, StoreUp: true, MgmtBound: true, CAReady: false, OrigDestOff: true})
	if noCA.Ready || !hasCode(noCA.Warnings, WarnCAMissing) {
		t.Fatalf("intercept without compiled CA must be unready: %+v", noCA)
	}
}

func TestEvaluateReadyDoesNotRequireInboxOrUpstreams(t *testing.T) {
	// Empty store (StoreUp means initialized, not non-empty) is ready.
	p := Evaluate(Facts{ProxyBound: true, StoreUp: true, MgmtOff: true, CAReady: true, OrigDestOff: true})
	if !p.Ready {
		t.Fatalf("empty initialized store must be ready: %+v", p)
	}
}

func TestEvaluateOrigDestOffReady(t *testing.T) {
	p := Evaluate(Facts{ProxyBound: true, StoreUp: true, MgmtOff: true, CAReady: true, OrigDestOff: true})
	if !p.Ready {
		t.Fatalf("OrigDestOff must be ready: %+v", p)
	}
	bound := Evaluate(Facts{ProxyBound: true, StoreUp: true, MgmtOff: true, CAReady: true, OrigDestBound: true})
	if !bound.Ready {
		t.Fatalf("OrigDestBound must be ready: %+v", bound)
	}
}

func TestEvaluateOrigDestEnabledUnbound(t *testing.T) {
	p := Evaluate(Facts{ProxyBound: true, StoreUp: true, MgmtOff: true, CAReady: true})
	if p.Ready {
		t.Fatal("orig-dest neither bound nor off must be unready")
	}
	if !hasCode(p.Warnings, WarnOrigDestUnbound) || !hasCode(p.Warnings, WarnListenerUnbound) {
		t.Fatalf("warnings=%v", p.Warnings)
	}
}

func TestWarningBound(t *testing.T) {
	p := Evaluate(Facts{})
	if len(p.Warnings) > MaxWarnings {
		t.Fatalf("warnings=%d", len(p.Warnings))
	}
}

func hasCode(ws []Warning, code string) bool {
	for _, w := range ws {
		if w.Code == code {
			return true
		}
	}
	return false
}

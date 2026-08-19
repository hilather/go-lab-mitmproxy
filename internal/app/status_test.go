package app

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/observability"
)

func TestStatusReadyUsesHealthFacts(t *testing.T) {
	svc, _ := mustBoot(t)
	st, err := svc.Status(context.Background(), actor())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Ready {
		t.Fatal("store-up app is ready without a listener probe")
	}
	svc.SetHealth(func() observability.Facts {
		return observability.Facts{ProxyBound: false, StoreUp: true, MgmtBound: true, CAReady: true}
	})
	st, err = svc.Status(context.Background(), actor())
	if err != nil {
		t.Fatal(err)
	}
	if st.Ready {
		t.Fatal("Status.Ready must follow Evaluate (proxy unbound)")
	}
}

func TestHealthFactsOrigDestOffFollowsLiveSpec(t *testing.T) {
	svc, _ := mustBoot(t)
	svc.SetHealth(func() observability.Facts {
		return observability.Facts{ProxyBound: true, StoreUp: true, MgmtBound: true, CAReady: true}
	})
	st, err := svc.Status(context.Background(), actor())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Ready {
		t.Fatal("live spec orig dest off must overlay OrigDestOff")
	}
	facts := svc.HealthFacts()
	if !facts.OrigDestOff {
		t.Fatalf("facts=%+v", facts)
	}
}

func TestStatusReadyRequiresCAWhenIntercept(t *testing.T) {
	svc, _ := mustBoot(t)
	svc.SetHealth(func() observability.Facts {
		return observability.Facts{ProxyBound: true, StoreUp: true, MgmtBound: true, CAReady: false, OrigDestOff: true}
	})
	// HealthFacts overwrites CAReady from the live snapshot (intercept off → true).
	st, err := svc.Status(context.Background(), actor())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Ready {
		t.Fatal("intercept off must keep CAReady")
	}
}

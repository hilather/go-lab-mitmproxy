package proxy

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestGuardLiteralLoopback(t *testing.T) {
	res, err := resolveThenGuard(context.Background(), nil, defaultTargets(), "127.0.0.1", "80")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Selected.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("selected %v", res.Selected)
	}
}

func TestGuardLiteralIMDS(t *testing.T) {
	_, err := resolveThenGuard(context.Background(), nil, defaultTargets(), "169.254.169.254", "80")
	if !errors.Is(err, errTargetDenied) {
		t.Fatalf("err=%v", err)
	}
}

func TestGuardLiteralLinkLocal(t *testing.T) {
	_, err := resolveThenGuard(context.Background(), nil, defaultTargets(), "169.254.1.1", "80")
	if !errors.Is(err, errTargetDenied) {
		t.Fatalf("err=%v", err)
	}
}

func TestGuardNameIMDS(t *testing.T) {
	r := mapResolver{"metadata.google.internal": {net.ParseIP("169.254.169.254")}}
	_, err := resolveThenGuard(context.Background(), r, defaultTargets(), "metadata.google.internal", "80")
	if !errors.Is(err, errTargetDenied) {
		t.Fatalf("err=%v", err)
	}
}

func TestGuardNameLinkLocal(t *testing.T) {
	r := mapResolver{"linklocal.test": {net.ParseIP("fe80::1")}}
	_, err := resolveThenGuard(context.Background(), r, defaultTargets(), "linklocal.test", "80")
	if !errors.Is(err, errTargetDenied) {
		t.Fatalf("err=%v", err)
	}
}

func TestGuardAnyDeniedRejectsWholeName(t *testing.T) {
	r := mapResolver{"mixed.test": {net.ParseIP("1.2.3.4"), net.ParseIP("169.254.169.254")}}
	_, err := resolveThenGuard(context.Background(), r, defaultTargets(), "mixed.test", "80")
	if !errors.Is(err, errTargetDenied) {
		t.Fatalf("err=%v", err)
	}
}

func TestGuardDenyHostsNoLookup(t *testing.T) {
	called := false
	r := lookupFunc(func(ctx context.Context, network, host string) ([]net.IP, error) {
		called = true
		return []net.IP{net.ParseIP("1.2.3.4")}, nil
	})
	tg := defaultTargets()
	tg.DenyHosts = []string{"evil.test"}
	_, err := resolveThenGuard(context.Background(), r, tg, "evil.test", "80")
	if !errors.Is(err, errTargetDenied) {
		t.Fatalf("err=%v", err)
	}
	if called {
		t.Fatal("denyHosts must not lookup")
	}
}

func TestGuardAllowHostsNoLookup(t *testing.T) {
	called := false
	r := lookupFunc(func(ctx context.Context, network, host string) ([]net.IP, error) {
		called = true
		return []net.IP{net.ParseIP("1.2.3.4")}, nil
	})
	tg := defaultTargets()
	tg.AllowHosts = []string{"*.lab"}
	_, err := resolveThenGuard(context.Background(), r, tg, "evil.com", "80")
	if !errors.Is(err, errTargetDenied) {
		t.Fatalf("err=%v", err)
	}
	if called {
		t.Fatal("allowHosts miss must not lookup")
	}
}

func TestGuardLiteralSkipsNameGlob(t *testing.T) {
	tg := defaultTargets()
	tg.AllowHosts = []string{"*.lab"}
	res, err := resolveThenGuard(context.Background(), nil, tg, "127.0.0.1", "9")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Selected.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("selected %v", res.Selected)
	}
}

func TestGuardDNSFailure(t *testing.T) {
	r := mapResolver{}
	_, err := resolveThenGuard(context.Background(), r, defaultTargets(), "missing.test", "80")
	if !errors.Is(err, errDNS) {
		t.Fatalf("err=%v", err)
	}
}

func TestPickAddrPrefersIPv6(t *testing.T) {
	got := pickAddr([]net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("2001:db8::1")})
	if !got.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("got %v", got)
	}
}

func TestMatchHost(t *testing.T) {
	if !matchHost("*.lab", "app.lab") {
		t.Fatal("*.lab should match app.lab")
	}
	if matchHost("*.lab", "lab") {
		t.Fatal("*.lab should not match lab")
	}
	if !matchHost("app.lab", "APP.LAB") {
		t.Fatal("exact match is case-insensitive")
	}
}

func defaultTargets() model.TargetsSpec {
	return model.TargetsSpec{
		DenyCloudMetadata: true,
		DenyLinkLocal:     true,
		AllowLoopback:     true,
	}
}

type lookupFunc func(ctx context.Context, network, host string) ([]net.IP, error)

func (f lookupFunc) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return f(ctx, network, host)
}

package rules

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestMutates(t *testing.T) {
	for _, typ := range []string{model.ActionBody, model.ActionStatus, model.ActionDrop, model.ActionBreakpoint, model.ActionRedirect} {
		if !Mutates(&Hit{Action: model.RuleActionSpec{Type: typ}}) {
			t.Fatalf("%s should mutate", typ)
		}
	}
	for _, typ := range []string{model.ActionDelay, model.ActionHeader, model.ActionSilent, model.ActionHang, ""} {
		if Mutates(&Hit{Action: model.RuleActionSpec{Type: typ}}) {
			t.Fatalf("%s should capture-only", typ)
		}
	}
	if Mutates(nil) {
		t.Fatal("nil")
	}
}

func TestClampDelay(t *testing.T) {
	if ClampDelay(-time.Second) != 0 || ClampDelay(0) != 0 {
		t.Fatal("negative/zero")
	}
	if ClampDelay(time.Hour) != MaxDelay {
		t.Fatal("cap 30s")
	}
	if ClampDelay(2*time.Second) != 2*time.Second {
		t.Fatal("passthrough")
	}
}

func TestClampBreakpointTimeout(t *testing.T) {
	if got := ClampBreakpointTimeout(0, 0); got != MinBreakpointTimeout {
		t.Fatalf("min %s", got)
	}
	if got := ClampBreakpointTimeout(time.Hour, 0); got != MaxBreakpointTimeout {
		t.Fatalf("max %s", got)
	}
	if got := ClampBreakpointTimeout(30*time.Second, 5*time.Second); got != 5*time.Second {
		t.Fatalf("store maxWait %s", got)
	}
}

func TestStatusFor(t *testing.T) {
	if StatusFor(&Hit{Action: model.RuleActionSpec{Type: model.ActionDrop}}) != DefaultDropStatus {
		t.Fatal("drop default 403")
	}
	if StatusFor(&Hit{Action: model.RuleActionSpec{Type: model.ActionDrop, Status: 451}}) != 451 {
		t.Fatal("drop status")
	}
	if StatusFor(&Hit{Action: model.RuleActionSpec{Type: model.ActionStatus}}) != DefaultSyntheticStatus {
		t.Fatal("status default 502")
	}
}

func TestSilentCloseDefaultsRST(t *testing.T) {
	if SilentClose(nil) != model.SilentCloseRST {
		t.Fatal("nil")
	}
	if SilentClose(&Hit{Action: model.RuleActionSpec{Type: model.ActionSilent}}) != model.SilentCloseRST {
		t.Fatal("empty silent.close")
	}
	if SilentClose(&Hit{Action: model.RuleActionSpec{Type: model.ActionSilent, Silent: model.RuleSilentSpec{Close: model.SilentCloseFIN}}}) != model.SilentCloseFIN {
		t.Fatal("fin")
	}
	if SilentClose(&Hit{Action: model.RuleActionSpec{Type: model.ActionHang, Hang: model.RuleHangSpec{Close: "nope"}}}) != model.SilentCloseRST {
		t.Fatal("unknown hang.close")
	}
}

func TestClampHangTimeout(t *testing.T) {
	if got := ClampHangTimeout(0, 0); got != MinHangTimeout {
		t.Fatalf("min %s", got)
	}
	if got := ClampHangTimeout(time.Hour, 0); got != MaxHangTimeout {
		t.Fatalf("max %s", got)
	}
	if got := ClampHangTimeout(10*time.Second, 2*time.Second); got != 2*time.Second {
		t.Fatalf("sessionTimeout %s", got)
	}
	if HangTimeout(&Hit{Action: model.RuleActionSpec{Hang: model.RuleHangSpec{Timeout: 5 * time.Second}}}) != 5*time.Second {
		t.Fatal("HangTimeout")
	}
}

func TestRedirectStatusAndLocation(t *testing.T) {
	if RedirectStatus(nil) != model.RedirectDefaultStatus {
		t.Fatal("nil default 302")
	}
	if RedirectStatus(&Hit{Action: model.RuleActionSpec{Redirect: model.RuleRedirectSpec{Status: 0}}}) != 302 {
		t.Fatal("empty → 302")
	}
	if RedirectStatus(&Hit{Action: model.RuleActionSpec{Redirect: model.RuleRedirectSpec{Status: 307}}}) != 307 {
		t.Fatal("307")
	}
	if RedirectStatus(&Hit{Action: model.RuleActionSpec{Redirect: model.RuleRedirectSpec{Status: 300}}}) != 302 {
		t.Fatal("illegal status")
	}
	if RedirectLocation(&Hit{Action: model.RuleActionSpec{Redirect: model.RuleRedirectSpec{Location: "  /x  "}}}) != "/x" {
		t.Fatal("trim")
	}
}

func TestApplyHeadersDeterministic(t *testing.T) {
	in := []model.Header{{Name: "X-A", Value: "1"}, {Name: "X-B", Value: "2"}, {Name: "X-C", Value: "3"}}
	out := ApplyHeaders(in, model.RuleHeadersSpec{
		Remove: []string{"x-b"},
		Set:    map[string]string{"X-Z": "z", "X-A": "new"},
	})
	want := []model.Header{{Name: "X-C", Value: "3"}, {Name: "X-A", Value: "new"}, {Name: "X-Z", Value: "z"}}
	if len(out) != len(want) {
		t.Fatalf("len %d want %d %+v", len(out), len(want), out)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("idx %d %+v want %+v", i, out[i], want[i])
		}
	}
}

func TestBodyReplace(t *testing.T) {
	b, ok := BodyReplace(&Hit{Action: model.RuleActionSpec{Type: model.ActionBody}})
	if !ok || len(b) != 0 {
		t.Fatal("body action empty replace is still a replace")
	}
	if _, ok := BodyReplace(&Hit{Action: model.RuleActionSpec{Type: model.ActionStatus}}); ok {
		t.Fatal("status without body keeps original")
	}
	got, ok := BodyReplace(&Hit{Action: model.RuleActionSpec{Type: model.ActionStatus, Body: model.RuleBodySpec{Replace: "x"}}})
	if !ok || string(got) != "x" {
		t.Fatal("status with body")
	}
	got, ok = BodyReplace(&Hit{Action: model.RuleActionSpec{Type: model.ActionRedirect, Body: model.RuleBodySpec{Replace: "go"}}})
	if !ok || string(got) != "go" {
		t.Fatal("redirect with body")
	}
	if _, ok := BodyReplace(&Hit{Action: model.RuleActionSpec{Type: model.ActionSilent}}); ok {
		t.Fatal("silent is capture-only")
	}
}

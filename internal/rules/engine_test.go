package rules

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestMasterSwitchDefaultOff(t *testing.T) {
	eng := New(model.RulesSpec{
		Enabled: false,
		Items: []model.RuleSpec{
			{ID: "drop-all", Enabled: true, Phase: model.RulePhaseRequest, Action: model.RuleActionSpec{Type: model.ActionDrop}},
		},
	})
	if eng.Match(model.RulePhaseRequest, Request{Path: "/", Method: "GET"}) != nil {
		t.Fatal("disabled master switch must match nothing")
	}
	if New(model.RulesSpec{}).Enabled() {
		t.Fatal("zero spec must be default-off")
	}
}

func TestFirstEnabledMatchWins(t *testing.T) {
	eng := snapshotEngine(true,
		model.RuleSpec{ID: "disabled", Enabled: false, Phase: model.RulePhaseRequest, Match: model.RuleMatchSpec{PathPrefix: "/"}, Action: model.RuleActionSpec{Type: model.ActionDrop}},
		model.RuleSpec{ID: "winner", Enabled: true, Phase: model.RulePhaseRequest, Match: model.RuleMatchSpec{PathPrefix: "/login"}, Action: model.RuleActionSpec{Type: model.ActionDelay, Delay: time.Second}},
		model.RuleSpec{ID: "later", Enabled: true, Phase: model.RulePhaseRequest, Match: model.RuleMatchSpec{PathPrefix: "/login"}, Action: model.RuleActionSpec{Type: model.ActionStatus, Status: 418}},
	)
	hit := eng.Match(model.RulePhaseRequest, Request{Path: "/login", Method: "POST"})
	if hit == nil || hit.ID != "winner" || hit.Action.Type != model.ActionDelay {
		t.Fatalf("hit %+v", hit)
	}
}

func TestPhaseSeparation(t *testing.T) {
	eng := snapshotEngine(true,
		model.RuleSpec{ID: "req", Enabled: true, Phase: model.RulePhaseRequest, Action: model.RuleActionSpec{Type: model.ActionDrop}},
		model.RuleSpec{ID: "resp", Enabled: true, Phase: model.RulePhaseResponse, Action: model.RuleActionSpec{Type: model.ActionHeader}},
	)
	if hit := eng.Match(model.RulePhaseRequest, Request{Path: "/"}); hit == nil || hit.ID != "req" {
		t.Fatalf("request %+v", hit)
	}
	if hit := eng.Match(model.RulePhaseResponse, Request{Path: "/"}); hit == nil || hit.ID != "resp" {
		t.Fatalf("response %+v", hit)
	}
}

func TestEmptyMatchMatchesEverything(t *testing.T) {
	eng := snapshotEngine(true,
		model.RuleSpec{ID: "any", Enabled: true, Phase: model.RulePhaseRequest, Action: model.RuleActionSpec{Type: model.ActionDelay}},
	)
	if hit := eng.Match(model.RulePhaseRequest, Request{Host: "x", Path: "/z", Method: "PUT"}); hit == nil || hit.ID != "any" {
		t.Fatalf("empty match %+v", hit)
	}
}

func TestMatchAND(t *testing.T) {
	item := model.RuleSpec{
		ID:      "and",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match: model.RuleMatchSpec{
			Host:           "*.lab.test",
			PathPrefix:     "/login",
			PathExact:      "/login",
			Method:         "POST",
			HeaderName:     "X-Token",
			HeaderContains: "abc",
		},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	}
	eng := snapshotEngine(true, item)
	ok := Request{
		Host:    "app.lab.test",
		Path:    "/login",
		Method:  "POST",
		Headers: []model.Header{{Name: "X-Token", Value: "xxabc"}},
	}
	if hit := eng.Match(model.RulePhaseRequest, ok); hit == nil {
		t.Fatal("expected AND match")
	}
	bad := ok
	bad.Method = "GET"
	if eng.Match(model.RulePhaseRequest, bad) != nil {
		t.Fatal("method mismatch must fail AND")
	}
	bad = ok
	bad.Path = "/login/extra"
	if eng.Match(model.RulePhaseRequest, bad) != nil {
		t.Fatal("pathExact must fail AND")
	}
	bad = ok
	bad.Host = "lab.test"
	if eng.Match(model.RulePhaseRequest, bad) != nil {
		t.Fatal("*.lab.test must not match lab.test")
	}
	bad = ok
	bad.Headers = []model.Header{{Name: "X-Token", Value: "nope"}}
	if eng.Match(model.RulePhaseRequest, bad) != nil {
		t.Fatal("headerContains must fail AND")
	}
}

func TestHostCaseInsensitive(t *testing.T) {
	eng := snapshotEngine(true, model.RuleSpec{
		ID: "h", Enabled: true, Phase: model.RulePhaseRequest,
		Match:  model.RuleMatchSpec{Host: "App.Lab.Test"},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	})
	if eng.Match(model.RulePhaseRequest, Request{Host: "app.lab.test", Path: "/"}) == nil {
		t.Fatal("host match is case-insensitive")
	}
}

func TestHeaderNamePresentWithoutContains(t *testing.T) {
	eng := snapshotEngine(true, model.RuleSpec{
		ID: "h", Enabled: true, Phase: model.RulePhaseRequest,
		Match:  model.RuleMatchSpec{HeaderName: "Authorization"},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	})
	if eng.Match(model.RulePhaseRequest, Request{Path: "/", Headers: []model.Header{{Name: "authorization", Value: "x"}}}) == nil {
		t.Fatal("header name present")
	}
	if eng.Match(model.RulePhaseRequest, Request{Path: "/"}) != nil {
		t.Fatal("missing header")
	}
}

func TestMatchProtocolAND(t *testing.T) {
	eng := snapshotEngine(true, model.RuleSpec{
		ID: "h2", Enabled: true, Phase: model.RulePhaseRequest,
		Match:  model.RuleMatchSpec{Protocol: model.FlowProtocolHTTP2},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	})
	if eng.Match(model.RulePhaseRequest, Request{Path: "/", Protocol: ""}) != nil {
		t.Fatal("empty request protocol must not match protocol: h2")
	}
	if eng.Match(model.RulePhaseRequest, Request{Path: "/", Protocol: model.FlowProtocolHTTP11}) != nil {
		t.Fatal("http/1.1 must not match protocol: h2")
	}
	if hit := eng.Match(model.RulePhaseRequest, Request{Path: "/", Protocol: model.FlowProtocolHTTP2}); hit == nil || hit.ID != "h2" {
		t.Fatalf("h2 %+v", hit)
	}
	if hit := eng.Match(model.RulePhaseRequest, Request{Path: "/", Protocol: "H2"}); hit == nil {
		t.Fatal("protocol match is case-insensitive")
	}

	anyProto := snapshotEngine(true, model.RuleSpec{
		ID: "any", Enabled: true, Phase: model.RulePhaseRequest,
		Match:  model.RuleMatchSpec{PathPrefix: "/"},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	})
	if anyProto.Match(model.RulePhaseRequest, Request{Path: "/", Protocol: model.FlowProtocolHTTP11}) == nil {
		t.Fatal("empty match.protocol still matches")
	}
}

func TestNilEngine(t *testing.T) {
	var e *Engine
	if e.Match(model.RulePhaseRequest, Request{}) != nil || e.Enabled() {
		t.Fatal("nil engine")
	}
}

func snapshotEngine(enabled bool, items ...model.RuleSpec) *Engine {
	return New(model.RulesSpec{Enabled: enabled, Items: items})
}

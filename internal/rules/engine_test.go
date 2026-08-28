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

func TestMatchPseudoHeaders(t *testing.T) {
	eng := snapshotEngine(true, model.RuleSpec{
		ID:      "login",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Match: model.RuleMatchSpec{
			Host:       "app.lab",
			PathPrefix: "/login",
			PathExact:  "/login",
			Method:     "POST",
			HeaderName: ":path",
		},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	})
	ok := Request{
		Headers: []model.Header{
			{Name: ":method", Value: "POST"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "app.lab:443"},
			{Name: ":path", Value: "/login?x=1"},
		},
	}
	if hit := eng.Match(model.RulePhaseRequest, ok); hit == nil || hit.ID != "login" {
		t.Fatalf("pseudos %+v", hit)
	}
	bad := ok
	bad.Headers = append([]model.Header(nil), ok.Headers...)
	bad.Headers[3].Value = "/other?x=1"
	if eng.Match(model.RulePhaseRequest, bad) != nil {
		t.Fatal(":path /other must not match /login")
	}
	bad = ok
	bad.Headers = append([]model.Header(nil), ok.Headers...)
	bad.Headers[0].Value = "GET"
	if eng.Match(model.RulePhaseRequest, bad) != nil {
		t.Fatal(":method GET must not match POST")
	}
	bad = ok
	bad.Headers = append([]model.Header(nil), ok.Headers...)
	bad.Headers[2].Value = "other.lab:443"
	if eng.Match(model.RulePhaseRequest, bad) != nil {
		t.Fatal(":authority other.lab must not match app.lab")
	}
}

func TestWebSocketPhaseFirstMatch(t *testing.T) {
	eng := snapshotEngine(true,
		model.RuleSpec{ID: "req", Enabled: true, Phase: model.RulePhaseRequest, Action: model.RuleActionSpec{Type: model.ActionDrop}},
		model.RuleSpec{ID: "drop-text", Enabled: true, Phase: model.RulePhaseWebSocket, Match: model.RuleMatchSpec{Opcode: model.RuleOpcodeText}, Action: model.RuleActionSpec{Type: model.ActionDrop}},
		model.RuleSpec{ID: "later", Enabled: true, Phase: model.RulePhaseWebSocket, Action: model.RuleActionSpec{Type: model.ActionBlock}},
	)
	in := Request{Protocol: model.FlowProtocolWebSocket, Opcode: model.RuleOpcodeText, Direction: model.WSDirectionClient, Path: "/ws"}
	hit := eng.Match(model.RulePhaseWebSocket, in)
	if hit == nil || hit.ID != "drop-text" || hit.Action.Type != model.ActionDrop {
		t.Fatalf("hit %+v", hit)
	}
	if eng.Match(model.RulePhaseWebSocket, Request{Protocol: model.FlowProtocolWebSocket, Opcode: model.RuleOpcodePing}) == nil {
		t.Fatal("later empty-match must still win on ping")
	}
}

func TestWebSocketMasterSwitchOff(t *testing.T) {
	eng := snapshotEngine(false,
		model.RuleSpec{ID: "drop", Enabled: true, Phase: model.RulePhaseWebSocket, Action: model.RuleActionSpec{Type: model.ActionDrop}},
	)
	if eng.Match(model.RulePhaseWebSocket, Request{Protocol: model.FlowProtocolWebSocket, Opcode: model.RuleOpcodeText}) != nil {
		t.Fatal("disabled master switch must match nothing")
	}
	if eng.HasEnabledWebSocket() {
		t.Fatal("disabled engine has no enabled websocket items")
	}
}

func TestWebSocketEmptyMatch(t *testing.T) {
	eng := snapshotEngine(true,
		model.RuleSpec{ID: "any", Enabled: true, Phase: model.RulePhaseWebSocket, Action: model.RuleActionSpec{Type: model.ActionDrop}},
	)
	if hit := eng.Match(model.RulePhaseWebSocket, Request{Protocol: model.FlowProtocolWebSocket, Path: "/z"}); hit == nil || hit.ID != "any" {
		t.Fatalf("empty match %+v", hit)
	}
}

func TestWebSocketOpcodeDirectionPayload(t *testing.T) {
	eng := snapshotEngine(true, model.RuleSpec{
		ID:      "secret",
		Enabled: true,
		Phase:   model.RulePhaseWebSocket,
		Match: model.RuleMatchSpec{
			Opcode:          model.RuleOpcodeText,
			Direction:       model.WSDirectionClient,
			PayloadContains: "secret",
		},
		Action: model.RuleActionSpec{Type: model.ActionDrop},
	})
	ok := Request{
		Protocol:  model.FlowProtocolWebSocket,
		Opcode:    model.RuleOpcodeText,
		Direction: model.WSDirectionClient,
		Payload:   []byte("the secret token"),
	}
	if hit := eng.Match(model.RulePhaseWebSocket, ok); hit == nil {
		t.Fatal("expected payloadContains hit")
	}
	bad := ok
	bad.Opcode = model.RuleOpcodeBinary
	if eng.Match(model.RulePhaseWebSocket, bad) != nil {
		t.Fatal("opcode mismatch")
	}
	bad = ok
	bad.Direction = model.WSDirectionOrigin
	if eng.Match(model.RulePhaseWebSocket, bad) != nil {
		t.Fatal("direction mismatch")
	}
	bad = ok
	bad.Payload = []byte("nope")
	if eng.Match(model.RulePhaseWebSocket, bad) != nil {
		t.Fatal("payload miss")
	}
	bad = ok
	bad.Payload = nil
	if eng.Match(model.RulePhaseWebSocket, bad) != nil {
		t.Fatal("nil payload must miss non-empty payloadContains")
	}
}

func TestWebSocketProtocolForced(t *testing.T) {
	eng := snapshotEngine(true, model.RuleSpec{
		ID:      "ws",
		Enabled: true,
		Phase:   model.RulePhaseWebSocket,
		Match:   model.RuleMatchSpec{Protocol: model.FlowProtocolWebSocket},
		Action:  model.RuleActionSpec{Type: model.ActionDrop},
	})
	if hit := eng.Match(model.RulePhaseWebSocket, Request{Protocol: model.FlowProtocolWebSocket, Opcode: model.RuleOpcodeText}); hit == nil {
		t.Fatal("match.protocol websocket must hit")
	}
	if eng.Match(model.RulePhaseWebSocket, Request{Protocol: model.FlowProtocolHTTP11, Opcode: model.RuleOpcodeText}) != nil {
		t.Fatal("http/1.1 must miss")
	}
	if eng.Match(model.RulePhaseWebSocket, Request{Protocol: model.FlowProtocolHTTP2, Opcode: model.RuleOpcodeText}) != nil {
		t.Fatal("h2 must miss")
	}
}

func TestRequestPhaseDoesNotWinOnWebSocketMatch(t *testing.T) {
	eng := snapshotEngine(true, model.RuleSpec{
		ID:      "req",
		Enabled: true,
		Phase:   model.RulePhaseRequest,
		Action:  model.RuleActionSpec{Type: model.ActionDrop},
	})
	if eng.Match(model.RulePhaseWebSocket, Request{Protocol: model.FlowProtocolWebSocket, Path: "/"}) != nil {
		t.Fatal("request-phase item must not win on Match(websocket)")
	}
	if eng.HasEnabledWebSocket() {
		t.Fatal("request-only engine must not report enabled websocket items")
	}
}

func TestOversizedPayloadContainsMissThenOpcodeWins(t *testing.T) {
	eng := snapshotEngine(true,
		model.RuleSpec{
			ID:      "secret",
			Enabled: true,
			Phase:   model.RulePhaseWebSocket,
			Match:   model.RuleMatchSpec{PayloadContains: "secret"},
			Action:  model.RuleActionSpec{Type: model.ActionDrop},
		},
		model.RuleSpec{
			ID:      "text",
			Enabled: true,
			Phase:   model.RulePhaseWebSocket,
			Match:   model.RuleMatchSpec{Opcode: model.RuleOpcodeText},
			Action:  model.RuleActionSpec{Type: model.ActionBlock},
		},
	)
	in := Request{Protocol: model.FlowProtocolWebSocket, Opcode: model.RuleOpcodeText, Direction: model.WSDirectionClient}
	if eng.NeedsFramePayload(in, 64, 4) {
		t.Fatal("oversized payloadContains must not demand a load")
	}
	hit := eng.Match(model.RulePhaseWebSocket, in)
	if hit == nil || hit.ID != "text" {
		t.Fatalf("later opcode-only must win when payload is nil: %+v", hit)
	}
}

func TestNeedsFramePayloadPathMissStillLoads(t *testing.T) {
	eng := snapshotEngine(true,
		model.RuleSpec{
			ID:      "admin",
			Enabled: true,
			Phase:   model.RulePhaseWebSocket,
			Match:   model.RuleMatchSpec{Opcode: model.RuleOpcodeText, PathPrefix: "/admin"},
			Action:  model.RuleActionSpec{Type: model.ActionDrop},
		},
		model.RuleSpec{
			ID:      "secret",
			Enabled: true,
			Phase:   model.RulePhaseWebSocket,
			Match:   model.RuleMatchSpec{PathPrefix: "/ws", PayloadContains: "secret"},
			Action:  model.RuleActionSpec{Type: model.ActionDrop},
		},
	)
	in := Request{Protocol: model.FlowProtocolWebSocket, Opcode: model.RuleOpcodeText, Path: "/ws"}
	if !eng.NeedsFramePayload(in, 6, 1024) {
		t.Fatal("earlier path-miss must still load later payloadContains")
	}
	in.Payload = []byte("secret")
	if hit := eng.Match(model.RulePhaseWebSocket, in); hit == nil || hit.ID != "secret" {
		t.Fatalf("later payloadContains %+v", hit)
	}
}

func TestNeedsFramePayloadEarlierOpcodeWinsWithoutLoad(t *testing.T) {
	eng := snapshotEngine(true,
		model.RuleSpec{
			ID:      "text",
			Enabled: true,
			Phase:   model.RulePhaseWebSocket,
			Match:   model.RuleMatchSpec{Opcode: model.RuleOpcodeText},
			Action:  model.RuleActionSpec{Type: model.ActionDrop},
		},
		model.RuleSpec{
			ID:      "secret",
			Enabled: true,
			Phase:   model.RulePhaseWebSocket,
			Match:   model.RuleMatchSpec{PayloadContains: "secret"},
			Action:  model.RuleActionSpec{Type: model.ActionBlock},
		},
	)
	in := Request{Protocol: model.FlowProtocolWebSocket, Opcode: model.RuleOpcodeText}
	if eng.NeedsFramePayload(in, 6, 1024) {
		t.Fatal("earlier opcode-only winner must not demand a load")
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

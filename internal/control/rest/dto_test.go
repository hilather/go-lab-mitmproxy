package rest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestFromFeatureList(t *testing.T) {
	empty := fromFeatureList(nil)
	if empty.Items == nil || len(empty.Items) != 0 {
		t.Fatalf("nil list=%+v", empty)
	}
	out := fromFeatureList(&app.FeatureList{
		RuntimeRevision: "sha256:abc",
		Generation:      4,
		Drifted:         true,
		Items: []app.Feature{{
			ID: "protocols.websocket", YAMLPath: "spec.protocols.websocket.enabled",
			Title: "WebSocket upgrade", Description: "d", Enabled: true,
			ApplyMode: app.FeatureApplyLive, Verb: app.FeatureVerbSetFeature,
		}},
	})
	if out.RuntimeRevision != "sha256:abc" || out.Generation != 4 || !out.Drifted || len(out.Items) != 1 {
		t.Fatalf("%+v", out)
	}
	if !out.Items[0].Enabled || out.Items[0].Verb != "setFeature" || out.Items[0].ApplyMode != "live" {
		t.Fatalf("item=%+v", out.Items[0])
	}
}

func TestFeaturesFromSpecCompactFromStatus(t *testing.T) {
	st := &app.Status{Features: app.StatusFeatures{HTTP2: true, SOCKS5: true, CompatFlowREST: true}}
	sp := &model.Spec{}
	sp.Protocols.HTTP2.Enabled = false
	sp.Protocols.HTTP2.ClientCleartext = true
	sp.Protocols.WebSocket.InspectFrames = true
	sp.Listeners.Proxy.AcceptSOCKS5 = false
	sp.Listeners.Proxy.AcceptBind = true
	sp.Compat.FlowREST.Enabled = false
	out := featuresFromSpec(st, sp)
	if !out.HTTP2 || !out.SOCKS5 || out.SOCKS4 || !out.CompatFlowREST {
		t.Fatalf("catalog five=%+v", out)
	}
	if !out.HTTP2ClientCleartext || !out.InspectWebSocketFrames || !out.AcceptBind {
		t.Fatalf("1.2 extras=%+v", out)
	}
	if out.OriginalDestination || out.SOCKS4 {
		t.Fatalf("unexpected compact true: %+v", out)
	}
	if out.HTTPAuth {
		t.Fatalf("httpAuth default=%+v", out)
	}
	sp.Proxy.HTTPAuth.Enabled = true
	on := featuresFromSpec(st, sp)
	if !on.HTTPAuth {
		t.Fatal("httpAuth must follow spec.proxy.httpAuth.enabled")
	}
	empty := featuresFromSpec(nil, nil)
	if empty.HTTP2 || empty.HTTP2ClientCleartext || empty.HTTPAuth {
		t.Fatalf("nil inputs=%+v", empty)
	}
}

func TestFromFlowSOCKSUser(t *testing.T) {
	f := &model.Flow{
		Protocol: model.FlowProtocolSOCKS5,
		SOCKS: &model.SOCKSInfo{
			Version: 5, ATYP: "ipv4", Dest: "127.0.0.1:80", Command: "connect", User: "lab-socks",
		},
	}
	out := fromFlow(f, false)
	if out.SOCKS == nil || out.SOCKS.User != "lab-socks" {
		t.Fatalf("socks=%+v", out.SOCKS)
	}
	b, err := json.Marshal(out.SOCKS)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"user":"lab-socks"`) {
		t.Fatalf("json=%s", b)
	}
	empty := fromFlow(&model.Flow{SOCKS: &model.SOCKSInfo{Version: 5, Command: "connect"}}, false)
	eb, err := json.Marshal(empty.SOCKS)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(eb), `"user"`) {
		t.Fatalf("empty user should omit: %s", eb)
	}
}

func TestFromFlowHTTP2Push(t *testing.T) {
	f := &model.Flow{
		Method:      "GET",
		Protocol:    model.FlowProtocolHTTP2,
		Intercepted: true,
		HTTP2: &model.HTTP2Info{
			StreamID:       2,
			ParentStreamID: 1,
			PromisedID:     2,
			Pushed:         true,
		},
	}
	out := fromFlow(f, false)
	if out.HTTP2 == nil || out.HTTP2.StreamID != 2 || out.HTTP2.ParentStreamID != 1 || out.HTTP2.PromisedID != 2 || !out.HTTP2.Pushed {
		t.Fatalf("http2=%+v", out.HTTP2)
	}
	b, err := json.Marshal(out.HTTP2)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"streamId":2,"parentStreamId":1,"promisedId":2,"pushed":true}` {
		t.Fatalf("json %s", got)
	}
	plain := fromFlow(&model.Flow{HTTP2: &model.HTTP2Info{StreamID: 7}}, true)
	b, err = json.Marshal(plain.HTTP2)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"streamId":7}` {
		t.Fatalf("omit empty push fields: %s", got)
	}
}

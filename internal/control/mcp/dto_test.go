package mcp

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
			ID: "listeners.originalDestination", YAMLPath: "spec.listeners.originalDestination.enabled",
			Title: "Original-destination REDIRECT", Description: "d", Enabled: false,
			ApplyMode: app.FeatureApplyReset, Verb: app.FeatureVerbReset,
		}},
	})
	if out.RuntimeRevision != "sha256:abc" || out.Generation != 4 || !out.Drifted || len(out.Items) != 1 {
		t.Fatalf("%+v", out)
	}
	if out.Items[0].Enabled || out.Items[0].Verb != "reset" || out.Items[0].ApplyMode != "reset" {
		t.Fatalf("item=%+v", out.Items[0])
	}
}

func TestFeaturesFromSpecCompactFromStatus(t *testing.T) {
	st := &app.Status{Features: app.StatusFeatures{HTTP2: true, SOCKS4: true, OriginalDestination: true}}
	sp := &model.Spec{}
	sp.Protocols.HTTP2.Origin = true
	sp.Listeners.Proxy.AcceptUDPAssociate = true
	out := featuresFromSpec(st, sp)
	if !out.HTTP2 || out.SOCKS5 || !out.SOCKS4 || !out.OriginalDestination || out.CompatFlowREST {
		t.Fatalf("catalog five=%+v", out)
	}
	if !out.HTTP2Origin || !out.AcceptUDPAssociate {
		t.Fatalf("1.2 extras=%+v", out)
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
}

func TestFromFlowHTTP2Push(t *testing.T) {
	out := fromFlow(&model.Flow{
		Method:      "GET",
		Protocol:    model.FlowProtocolHTTP2,
		Intercepted: true,
		HTTP2: &model.HTTP2Info{
			StreamID:       2,
			ParentStreamID: 1,
			PromisedID:     2,
			Pushed:         true,
		},
	}, false)
	if out.HTTP2 == nil || !out.HTTP2.Pushed || out.HTTP2.ParentStreamID != 1 || out.HTTP2.PromisedID != 2 {
		t.Fatalf("http2=%+v", out.HTTP2)
	}
	b, err := json.Marshal(out.HTTP2)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"streamId":2,"parentStreamId":1,"promisedId":2,"pushed":true}` {
		t.Fatalf("json %s", got)
	}
}

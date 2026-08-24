package rest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

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

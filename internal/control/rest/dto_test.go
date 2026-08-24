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

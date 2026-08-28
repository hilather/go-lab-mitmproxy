package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/rules"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestToolsRegisteredFromRegistry(t *testing.T) {
	s, _ := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	seen := map[string]bool{}
	for tool, err := range cs.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		seen[tool.Name] = true
		if tool.InputSchema == nil {
			t.Errorf("%s missing input schema", tool.Name)
		}
	}
	want := capabilities.Tools()
	if len(seen) != len(want) {
		t.Errorf("live tools=%d registry=%d", len(seen), len(want))
	}
	for _, name := range want {
		if !seen[name] {
			t.Errorf("missing tool %s", name)
		}
	}
	for name := range seen {
		found := false
		for _, w := range want {
			if w == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("extra live tool %s", name)
		}
	}
	if seen["health.live"] || seen["mitm_health_live"] {
		t.Fatal("health live must not be a tool")
	}
}

func TestResourcesRegisteredFromRegistry(t *testing.T) {
	s, _ := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	seen := map[string]bool{}
	for r, err := range cs.Resources(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		seen[r.URI] = true
	}
	for tmpl, err := range cs.ResourceTemplates(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		seen[tmpl.URITemplate] = true
	}
	want := capabilities.Resources()
	if len(seen) != len(want) {
		t.Errorf("live resources=%d registry=%d", len(seen), len(want))
	}
	for _, uri := range want {
		if !seen[uri] {
			t.Errorf("missing resource %s", uri)
		}
	}
	for uri := range seen {
		found := false
		for _, w := range want {
			if w == uri {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("extra live resource %s", uri)
		}
	}
}

func TestContractReads(t *testing.T) {
	s, svc := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)

	ver := structuredMap(t, callTool(t, cs, "mitm_version_get", map[string]any{}))
	if ver["protocols"] == nil {
		t.Fatalf("version=%v", ver)
	}
	caps := structuredMap(t, callTool(t, cs, "mitm_capabilities_get", map[string]any{}))
	if caps["capabilities"] == nil {
		t.Fatalf("capabilities=%v", caps)
	}
	st := structuredMap(t, callTool(t, cs, "mitm_status_get", map[string]any{}))
	if st["revisions"] == nil || st["ca"] == nil {
		t.Fatalf("status=%v", st)
	}
	feat, _ := st["features"].(map[string]any)
	if feat == nil {
		t.Fatalf("status missing features: %v", st)
	}
	for _, k := range []string{"http2", "socks5", "socks4", "originalDestination", "compatFlowREST"} {
		if _, ok := feat[k]; !ok {
			t.Fatalf("status.features missing %s: %v", k, feat)
		}
	}
	if _, ok := feat["catalog"]; ok {
		t.Fatalf("status.features must not nest catalog: %v", feat)
	}
	flist := structuredMap(t, callTool(t, cs, "mitm_features_list", map[string]any{}))
	fitems, _ := flist["items"].([]any)
	if len(fitems) != 11 {
		t.Fatalf("features items=%v", flist)
	}
	if flist["runtimeRevision"] == "" {
		t.Fatalf("features missing runtimeRevision: %v", flist)
	}
	schema := callTool(t, cs, "mitm_schema_get", map[string]any{})
	raw, _ := json.Marshal(schema.StructuredContent)
	if !strings.Contains(string(raw), "labmitm.dev/v1alpha1") {
		t.Fatalf("schema missing api version: %s", raw)
	}

	state := structuredMap(t, callTool(t, cs, "mitm_state_get", map[string]any{}))
	if state["runtimeRevision"] == "" {
		t.Fatalf("state=%v", state)
	}

	id := insertFlow(t, svc, "app.lab")
	list := structuredMap(t, callTool(t, cs, "mitm_flows_list", map[string]any{"limit": 1}))
	if list["storeGeneration"] == nil {
		t.Fatalf("list=%v", list)
	}
	items, _ := list["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items=%v", list)
	}
	item := items[0].(map[string]any)
	req, _ := item["request"].(map[string]any)
	if _, ok := req["body"]; ok {
		t.Fatal("list item must omit bodies")
	}

	got := structuredMap(t, callTool(t, cs, "mitm_flow_get", map[string]any{"id": id}))
	req, _ = got["request"].(map[string]any)
	if req["body"] == nil {
		t.Fatalf("get must include body: %v", got)
	}
	rawReq := structuredMap(t, callTool(t, cs, "mitm_flow_request_get", map[string]any{"id": id}))
	if rawReq["body"] != "req" || rawReq["side"] != "request" {
		t.Fatalf("request body=%v", rawReq)
	}
	missing := callToolExpectError(t, cs, "mitm_flow_get", map[string]any{"id": "01AAAAAAAAAAAAAAAAAAAAAAAA"})
	if domainCode(t, missing) != "not_found" {
		t.Fatalf("missing flow error=%v", missing)
	}

	ca := structuredMap(t, callTool(t, cs, "mitm_ca_get", map[string]any{}))
	pem, _ := ca["pem"].(string)
	if strings.Contains(pem, "PRIVATE KEY") {
		t.Fatal("mitm_ca_get leaked a private key")
	}
	if !strings.Contains(pem, "BEGIN CERTIFICATE") {
		t.Fatalf("ca=%v", ca)
	}

	featRes, err := cs.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: "labmitm://features"})
	if err != nil {
		t.Fatal(err)
	}
	if len(featRes.Contents) == 0 || !strings.Contains(featRes.Contents[0].Text, `"items"`) {
		t.Fatalf("resource features=%+v", featRes)
	}

	stateRes, err := cs.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: "labmitm://state"})
	if err != nil {
		t.Fatal(err)
	}
	if len(stateRes.Contents) == 0 || !strings.Contains(stateRes.Contents[0].Text, "runtimeRevision") {
		t.Fatalf("resource state=%+v", stateRes)
	}
	flowRes, err := cs.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: "labmitm://flows/" + id})
	if err != nil {
		t.Fatal(err)
	}
	if len(flowRes.Contents) == 0 || !strings.Contains(flowRes.Contents[0].Text, `"id"`) {
		t.Fatalf("resource flow=%+v", flowRes)
	}
}

func TestContractMutations(t *testing.T) {
	s, _ := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)

	state := structuredMap(t, callTool(t, cs, "mitm_state_get", map[string]any{}))
	rev, _ := state["runtimeRevision"].(string)
	args := map[string]any{
		"expectedRevision": rev,
		"reason":           "enable rules",
		"operations": []model.Operation{{
			Op:    model.OpReplaceRules,
			Rules: &model.RulesSpec{Enabled: true, Items: []model.RuleSpec{}},
		}},
	}
	val := structuredMap(t, callTool(t, cs, "mitm_state_validate", map[string]any{
		"operations": []model.Operation{{
			Op:    model.OpReplaceRules,
			Rules: &model.RulesSpec{Enabled: true, Items: []model.RuleSpec{}},
		}},
	}))
	if val["candidateRevision"] == nil && val["previousRevision"] == nil {
		t.Fatalf("validate=%v", val)
	}
	plan := structuredMap(t, callTool(t, cs, "mitm_change_plan", args))
	if plan["candidateRevision"] == rev {
		t.Fatal("plan did not change revision")
	}
	bad := callToolExpectError(t, cs, "mitm_change_apply", map[string]any{
		"expectedRevision": "sha256:deadbeef",
		"operations": []model.Operation{{
			Op:    model.OpReplaceRules,
			Rules: &model.RulesSpec{Enabled: true, Items: []model.RuleSpec{}},
		}},
	})
	if domainCode(t, bad) != "revision_conflict" {
		t.Fatalf("apply conflict=%v", bad)
	}
	apply := structuredMap(t, callTool(t, cs, "mitm_change_apply", args))
	if apply["applied"] != true {
		t.Fatalf("apply=%v", apply)
	}
	exp := structuredMap(t, callTool(t, cs, "mitm_state_export", map[string]any{"format": "yaml"}))
	body, _ := exp["body"].(string)
	if !strings.Contains(body, "apiVersion") {
		t.Fatalf("export missing body: %v", exp)
	}
	reset := structuredMap(t, callTool(t, cs, "mitm_state_reset", map[string]any{"reason": "test"}))
	if reset["applied"] != true {
		t.Fatalf("reset=%v", reset)
	}
}

func TestContractReplaceRulesBlockModes(t *testing.T) {
	s, _ := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	state := structuredMap(t, callTool(t, cs, "mitm_state_get", map[string]any{}))
	rev, _ := state["runtimeRevision"].(string)
	action := func(typ string, extra map[string]any) map[string]any {
		a := map[string]any{
			"type":           typ,
			"delay":          int64(0),
			"bytesPerSecond": int64(0),
			"status":         0,
			"headers": map[string]any{
				"set":    map[string]string{},
				"remove": []string{},
			},
			"body":       map[string]any{"replace": ""},
			"breakpoint": map[string]any{"timeout": int64(0)},
			"silent":     map[string]any{"close": ""},
			"hang":       map[string]any{"timeout": int64(0), "close": ""},
			"redirect":   map[string]any{"location": "", "status": 0},
		}
		for k, v := range extra {
			a[k] = v
		}
		return a
	}
	ops := []map[string]any{{
		"op": "replaceRules",
		"rules": map[string]any{
			"enabled": true,
			"items": []map[string]any{
				{"id": "silent-login", "enabled": true, "phase": "request", "match": map[string]any{"host": "", "pathPrefix": "", "pathExact": "", "method": "", "headerName": "", "headerContains": "", "protocol": "", "opcode": "", "direction": "", "payloadContains": ""}, "action": action("silent", map[string]any{"silent": map[string]any{"close": "rst"}})},
				{"id": "hang-login", "enabled": true, "phase": "request", "match": map[string]any{"host": "", "pathPrefix": "", "pathExact": "", "method": "", "headerName": "", "headerContains": "", "protocol": "", "opcode": "", "direction": "", "payloadContains": ""}, "action": action("hang", map[string]any{"hang": map[string]any{"timeout": int64(time.Second), "close": ""}})},
				{"id": "redir-login", "enabled": true, "phase": "request", "match": map[string]any{"host": "", "pathPrefix": "", "pathExact": "", "method": "", "headerName": "", "headerContains": "", "protocol": "", "opcode": "", "direction": "", "payloadContains": ""}, "action": action("redirect", map[string]any{"redirect": map[string]any{"location": "/x", "status": 0}})},
			},
		},
	}}
	valRes := callTool(t, cs, "mitm_state_validate", map[string]any{"operations": ops})
	if valRes.IsError {
		t.Fatalf("validate error: %s", firstText(valRes))
	}
	_ = structuredMap(t, valRes)
	apply := structuredMap(t, callTool(t, cs, "mitm_change_apply", map[string]any{
		"expectedRevision": rev,
		"reason":           "block modes",
		"operations":       ops,
	}))
	if apply["applied"] != true {
		t.Fatalf("apply=%v", apply)
	}
	bad := callToolExpectError(t, cs, "mitm_state_validate", map[string]any{
		"operations": []map[string]any{{
			"op": "replaceRules",
			"rules": map[string]any{
				"enabled": true,
				"items": []map[string]any{
					{"id": "bad", "enabled": true, "phase": "request", "match": map[string]any{"host": "", "pathPrefix": "", "pathExact": "", "method": "", "headerName": "", "headerContains": "", "protocol": "", "opcode": "", "direction": "", "payloadContains": ""}, "action": action("http_status", map[string]any{"status": 403})},
				},
			},
		}},
	})
	if domainCode(t, bad) != "validation_failed" {
		t.Fatalf("http_status=%v", bad)
	}
}

func TestContractThrottleReplaceRules(t *testing.T) {
	s, svc := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)

	state := structuredMap(t, callTool(t, cs, "mitm_state_get", map[string]any{}))
	rev, _ := state["runtimeRevision"].(string)
	// MCP schema is inferred from Rule*Spec (no omitempty). Initialize maps
	// so json.Marshal emits {} / [] instead of null (schema type object/array).
	throttleRule := func(id string, bps int64, pathPrefix string) model.Operation {
		return model.Operation{
			Op: model.OpReplaceRules,
			Rules: &model.RulesSpec{
				Enabled: true,
				Items: []model.RuleSpec{{
					ID:      id,
					Enabled: true,
					Phase:   model.RulePhaseResponse,
					Match:   model.RuleMatchSpec{PathPrefix: pathPrefix},
					Action: model.RuleActionSpec{
						Type:           model.ActionThrottle,
						BytesPerSecond: bps,
						Headers: model.RuleHeadersSpec{
							Set:    map[string]string{},
							Remove: []string{},
						},
					},
				}},
			},
		}
	}
	bad := callToolExpectError(t, cs, "mitm_change_apply", map[string]any{
		"expectedRevision": rev,
		"reason":           "invalid throttle",
		"operations":       []model.Operation{throttleRule("bad-bps", 0, "")},
	})
	if domainCode(t, bad) != "validation_failed" {
		t.Fatalf("apply invalid=%v", bad)
	}

	apply := structuredMap(t, callTool(t, cs, "mitm_change_apply", map[string]any{
		"expectedRevision": rev,
		"reason":           "enable throttle",
		"operations":       []model.Operation{throttleRule("slow-download", 8192, "/big")},
	}))
	if apply["applied"] != true {
		t.Fatalf("apply=%v", apply)
	}
	hit := svc.Active().Rules.Match(model.RulePhaseResponse, rules.Request{Path: "/big/x"})
	if hit == nil || hit.Action.Type != model.ActionThrottle || hit.Action.BytesPerSecond != 8192 {
		t.Fatalf("compiled hit=%+v", hit)
	}
}

func TestWaitTimeout(t *testing.T) {
	s, svc := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	insertFlow(t, svc, "wait.lab")
	wait := structuredMap(t, callTool(t, cs, "mitm_flows_wait", map[string]any{
		"filter":  map[string]any{"host": "wait.lab"},
		"timeout": "1s",
	}))
	id, _ := wait["id"].(string)
	if id == "" {
		t.Fatalf("wait=%v", wait)
	}
	timed := callToolExpectError(t, cs, "mitm_flows_wait", map[string]any{
		"filter":  map[string]any{"host": "never.lab"},
		"timeout": "1ms",
	})
	if domainCode(t, timed) != "timeout" {
		t.Fatalf("wait timeout=%v", timed)
	}
}

func TestContractWebSocketFrames(t *testing.T) {
	s, svc := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	res, err := svc.Inbox().Insert(context.Background(), svc.Inbox().Epoch(), &model.Flow{
		Host:     "ws.lab",
		Method:   "GET",
		URL:      "http://ws.lab/ws",
		Scheme:   "http",
		Protocol: model.FlowProtocolWebSocket,
		State:    model.FlowStateCompleted,
		Status:   101,
		RuleIDs:  []string{"drop-secret", "kill-bin"},
		WebSocket: &model.WebSocketInfo{
			FrameCount: 3,
			Frames: []model.WebSocketFrame{
				{
					Direction: model.WSDirectionClient,
					Opcode:    "text",
					OpcodeNum: 1,
					Fin:       true,
					Masked:    true,
					Payload:   []byte("hello"),
					Size:      5,
				},
				{
					Direction: model.WSDirectionClient,
					Opcode:    "text",
					OpcodeNum: 1,
					Fin:       true,
					Masked:    true,
					Payload:   []byte("secret"),
					Size:      6,
					Action:    model.ActionDrop,
				},
				{
					Direction: model.WSDirectionClient,
					Opcode:    "binary",
					OpcodeNum: 2,
					Fin:       true,
					Masked:    true,
					Payload:   []byte("xx"),
					Size:      2,
					Action:    model.ActionBlock,
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := res.ID

	list := structuredMap(t, callTool(t, cs, "mitm_flows_list", map[string]any{"limit": 1}))
	items, _ := list["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items=%v", list)
	}
	ws, _ := items[0].(map[string]any)["websocket"].(map[string]any)
	if ws == nil {
		t.Fatalf("list missing websocket: %v", list)
	}
	if _, ok := ws["frames"]; ok {
		t.Fatal("list item must omit frames")
	}
	if ws["frameCount"] != float64(3) {
		t.Fatalf("frameCount=%v", ws["frameCount"])
	}

	got := structuredMap(t, callTool(t, cs, "mitm_flow_get", map[string]any{"id": id}))
	ids, _ := got["ruleIds"].([]any)
	if len(ids) != 2 || ids[0] != "drop-secret" || ids[1] != "kill-bin" {
		t.Fatalf("ruleIds=%v", got["ruleIds"])
	}
	gws, _ := got["websocket"].(map[string]any)
	frames, _ := gws["frames"].([]any)
	if len(frames) != 3 {
		t.Fatalf("get frames=%v", got)
	}
	fr := frames[0].(map[string]any)
	if fr["payload"] != "hello" {
		t.Fatalf("payload=%v (must be string, not base64)", fr["payload"])
	}
	if _, ok := fr["action"]; ok {
		t.Fatal("forwarded frame must omit action")
	}
	if _, ok := fr["maskKey"]; ok {
		t.Fatal("maskKey must not be exported")
	}
	dropped := frames[1].(map[string]any)
	if dropped["action"] != model.ActionDrop || dropped["payload"] != "secret" {
		t.Fatalf("dropped frame %+v", dropped)
	}
	blocked := frames[2].(map[string]any)
	if blocked["action"] != model.ActionBlock || blocked["payload"] != "xx" {
		t.Fatalf("blocked frame %+v", blocked)
	}

	err = callToolExpectError(t, cs, "mitm_flow_replay", map[string]any{"id": id})
	if domainCode(t, err) != "validation_failed" {
		t.Fatalf("replay=%v", err)
	}
}

func TestContractWebSocketFrameRules(t *testing.T) {
	s, _ := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	schema := callTool(t, cs, "mitm_schema_get", map[string]any{})
	raw, _ := json.Marshal(schema.StructuredContent)
	if !strings.Contains(string(raw), `"websocket"`) || !strings.Contains(string(raw), `"block"`) || !strings.Contains(string(raw), `"payloadContains"`) {
		t.Fatalf("schema.get must list websocket/block/payloadContains: %s", raw)
	}
	state := structuredMap(t, callTool(t, cs, "mitm_state_get", map[string]any{}))
	rev, _ := state["runtimeRevision"].(string)
	res := callTool(t, cs, "mitm_change_apply", map[string]any{
		"expectedRevision": rev,
		"reason":           "websocket frame rules",
		"operations": []map[string]any{{
			"op": model.OpReplaceRules,
			"rules": map[string]any{
				"enabled": true,
				"items": []map[string]any{{
					"id": "drop-secret", "enabled": true, "phase": model.RulePhaseWebSocket,
					"match": map[string]any{
						"host": "", "pathPrefix": "", "pathExact": "", "method": "",
						"headerName": "", "headerContains": "", "protocol": "",
						"opcode": model.RuleOpcodeText, "direction": "", "payloadContains": "secret",
					},
					"action": map[string]any{
						"type": model.ActionDrop, "delay": 0, "bytesPerSecond": 0, "status": 0,
						"headers":    map[string]any{"set": map[string]string{}, "remove": []string{}},
						"body":       map[string]any{"replace": ""},
						"breakpoint": map[string]any{"timeout": 0},
						"silent":     map[string]any{"close": ""},
						"hang":       map[string]any{"timeout": 0, "close": ""},
						"redirect":   map[string]any{"location": "", "status": 0},
					},
				}},
			},
		}},
	})
	if res.IsError {
		t.Fatalf("apply error: %s structured=%v", firstText(res), res.StructuredContent)
	}
	apply := structuredMap(t, res)
	if apply["applied"] != true {
		t.Fatalf("apply=%v", apply)
	}
	exp := structuredMap(t, callTool(t, cs, "mitm_state_export", map[string]any{"format": "json"}))
	body, _ := exp["body"].(string)
	if !strings.Contains(body, `"phase":"websocket"`) {
		t.Fatalf("export missing websocket rule: %v", exp)
	}
}

func TestContractGRPC(t *testing.T) {
	s, svc := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	res, err := svc.Inbox().Insert(context.Background(), svc.Inbox().Epoch(), &model.Flow{
		Host:     "grpc.lab",
		Method:   "POST",
		URL:      "https://grpc.lab/svc/Method",
		Scheme:   "https",
		Protocol: model.FlowProtocolHTTP2,
		State:    model.FlowStateCompleted,
		Status:   200,
		GRPC: &model.GRPCInfo{
			ContentType: "application/grpc",
			Messages: []model.GRPCMessage{{
				Length: 4,
				Fields: []model.ProtoField{{Number: 1, WireType: 2, Text: "hi"}},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := res.ID

	list := structuredMap(t, callTool(t, cs, "mitm_flows_list", map[string]any{"limit": 1}))
	items, _ := list["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items=%v", list)
	}
	g, _ := items[0].(map[string]any)["grpc"].(map[string]any)
	if g == nil {
		t.Fatalf("list missing grpc: %v", list)
	}
	if _, ok := g["messages"]; ok {
		t.Fatal("list item must omit messages")
	}
	if g["contentType"] != "application/grpc" {
		t.Fatalf("contentType=%v", g["contentType"])
	}

	got := structuredMap(t, callTool(t, cs, "mitm_flow_get", map[string]any{"id": id}))
	gg, _ := got["grpc"].(map[string]any)
	msgs, _ := gg["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("get messages=%v", got)
	}
	fields, _ := msgs[0].(map[string]any)["fields"].([]any)
	if len(fields) != 1 || fields[0].(map[string]any)["text"] != "hi" {
		t.Fatalf("fields=%v", fields)
	}
}

func TestHealthNotRegisteredAsTools(t *testing.T) {
	s, _ := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	for tool, err := range cs.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(tool.Name, "health") || tool.Name == "health.live" || tool.Name == "health.ready" {
			t.Fatalf("health probe leaked as tool %q", tool.Name)
		}
	}
}

func callToolExpectError(t *testing.T, cs *sdk.ClientSession, name string, args any) error {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return err
	}
	if res != nil && res.IsError {
		raw, _ := json.Marshal(res.StructuredContent)
		return &toolDomainError{raw: raw, text: firstText(res)}
	}
	t.Fatalf("CallTool %s: want error", name)
	return nil
}

type toolDomainError struct {
	raw  []byte
	text string
}

func (e *toolDomainError) Error() string { return e.text }

func firstText(res *sdk.CallToolResult) string {
	if res == nil {
		return ""
	}
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			return tc.Text
		}
	}
	return "tool error"
}

func domainCode(t *testing.T, err error) string {
	t.Helper()
	var te *toolDomainError
	if errors.As(err, &te) && len(te.raw) > 0 {
		var payload struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(te.raw, &payload) == nil && payload.Code != "" {
			return payload.Code
		}
	}
	var werr *jsonrpc.Error
	if errors.As(err, &werr) && len(werr.Data) > 0 {
		var payload struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(werr.Data, &payload) == nil && payload.Code != "" {
			return payload.Code
		}
	}
	s := err.Error()
	for _, code := range []string{"not_found", "revision_conflict", "idempotency_conflict", "validation_failed", "timeout"} {
		if strings.Contains(s, code) {
			return code
		}
	}
	return s
}

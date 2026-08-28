package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/auth"
	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

func TestRoutesRegisteredFromRegistry(t *testing.T) {
	s, _ := newTestServer(t)
	if len(s.routes) == 0 {
		t.Fatal("no routes")
	}
	seen := map[string]bool{}
	for _, rt := range s.routes {
		seen[rt.method+" "+rt.path] = true
	}
	for _, c := range capabilities.All() {
		for _, b := range c.REST {
			ref := strings.ToUpper(b.Method) + " " + b.Path
			if !seen[ref] {
				t.Errorf("missing registry route %s", ref)
			}
		}
	}
}

func TestCompileRoutesHasNoCompat(t *testing.T) {
	s, _ := newTestServer(t)
	for _, rt := range s.routes {
		if strings.Contains(rt.path, "/compat") {
			t.Errorf("compileRoutes saw %s %s", rt.method, rt.path)
		}
	}
}

func TestContractReads(t *testing.T) {
	s, svc := newTestServer(t)
	h := s.Handler()

	live := doReqAuth(t, h, http.MethodGet, "/v1/health/live", "", "")
	requireStatus(t, live, http.StatusOK)
	if decodeJSON(t, live)["status"] != "ok" {
		t.Fatalf("live=%s", live.Body.String())
	}

	ready := doReqAuth(t, h, http.MethodGet, "/v1/health/ready", "", "")
	requireStatus(t, ready, http.StatusOK)

	ver := doReq(t, h, http.MethodGet, "/v1/version", "")
	requireStatus(t, ver, http.StatusOK)
	if decodeJSON(t, ver)["protocols"] == nil {
		t.Fatalf("version=%s", ver.Body.String())
	}

	caps := doReq(t, h, http.MethodGet, "/v1/capabilities", "")
	requireStatus(t, caps, http.StatusOK)
	clist, _ := decodeJSON(t, caps)["capabilities"].([]any)
	if len(clist) == 0 {
		t.Fatal("empty capabilities")
	}

	st := doReq(t, h, http.MethodGet, "/v1/status", "")
	requireStatus(t, st, http.StatusOK)
	body := decodeJSON(t, st)
	if body["revisions"] == nil || body["ca"] == nil {
		t.Fatalf("status=%s", st.Body.String())
	}
	feat, _ := body["features"].(map[string]any)
	if feat == nil {
		t.Fatalf("status missing features: %s", st.Body.String())
	}
	for _, k := range []string{
		"http2", "socks5", "socks4", "originalDestination", "compatFlowREST",
		"http2ClientCleartext", "http2Origin", "http2ExtendedConnect", "http2CapturePush", "http2GRPCDecode",
		"inspectWebSocketFrames", "acceptBind", "acceptUDPAssociate", "acceptUserPass",
	} {
		v, ok := feat[k]
		if !ok {
			t.Fatalf("status.features missing %s: %s", k, st.Body.String())
		}
		if v != false {
			t.Fatalf("status.features.%s=%v want false", k, v)
		}
	}
	if _, ok := feat["catalog"]; ok {
		t.Fatalf("status.features must not nest catalog: %s", st.Body.String())
	}
	if _, ok := feat["items"]; ok {
		t.Fatalf("status.features must not nest catalog items: %s", st.Body.String())
	}

	schema := doReq(t, h, http.MethodGet, "/v1/schema/config", "")
	requireStatus(t, schema, http.StatusOK)
	if !strings.Contains(schema.Body.String(), "labmitm.dev/v1alpha1") {
		t.Fatalf("schema missing api version")
	}

	state := doReq(t, h, http.MethodGet, "/v1/state", "")
	requireStatus(t, state, http.StatusOK)
	if decodeJSON(t, state)["runtimeRevision"] == "" {
		t.Fatalf("state=%s", state.Body.String())
	}

	id := insertFlow(t, svc, "app.lab")
	list := doReq(t, h, http.MethodGet, "/v1/flows?limit=1", "")
	requireStatus(t, list, http.StatusOK)
	lm := decodeJSON(t, list)
	if lm["storeGeneration"] == nil {
		t.Fatalf("list=%s", list.Body.String())
	}
	items, _ := lm["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items=%s", list.Body.String())
	}
	item := items[0].(map[string]any)
	req, _ := item["request"].(map[string]any)
	if _, ok := req["body"]; ok {
		t.Fatal("list item must omit bodies")
	}

	got := doReq(t, h, http.MethodGet, "/v1/flows/"+id, "")
	requireStatus(t, got, http.StatusOK)
	gm := decodeJSON(t, got)
	req, _ = gm["request"].(map[string]any)
	if req["body"] == nil {
		t.Fatalf("get must include body: %s", got.Body.String())
	}

	raw := doReq(t, h, http.MethodGet, "/v1/flows/"+id+"/request", "")
	requireStatus(t, raw, http.StatusOK)
	if raw.Body.String() != "req" {
		t.Fatalf("request body %q", raw.Body.String())
	}
	if !strings.Contains(raw.Header().Get("Content-Type"), "application/octet-stream") {
		t.Fatalf("request body type=%s", raw.Header().Get("Content-Type"))
	}

	missing := doReq(t, h, http.MethodGet, "/v1/flows/01AAAAAAAAAAAAAAAAAAAAAAAA", "")
	requireProblem(t, missing, http.StatusNotFound, "not_found")

	ca := doReq(t, h, http.MethodGet, "/v1/ca", "")
	requireStatus(t, ca, http.StatusOK)
	if !strings.Contains(ca.Header().Get("Content-Type"), "application/x-pem-file") {
		t.Fatalf("ca type=%s", ca.Header().Get("Content-Type"))
	}
	if strings.Contains(ca.Body.String(), "PRIVATE KEY") {
		t.Fatal("GET /v1/ca leaked a private key")
	}
	if !strings.Contains(ca.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("ca pem=%s", ca.Body.String())
	}
}

func TestFlowBodyDoesNotReflectCapturedHTMLType(t *testing.T) {
	s, svc := newTestServer(t)
	html := []byte("<html><script>alert(1)</script></html>")
	res, err := svc.Inbox().Insert(t.Context(), svc.Inbox().Epoch(), &model.Flow{
		Host:     "app.lab",
		Method:   "GET",
		URL:      "http://app.lab/",
		Scheme:   "http",
		Protocol: model.FlowProtocolHTTP11,
		State:    model.FlowStateCompleted,
		Status:   200,
		Request:  model.HTTPMessage{Body: []byte("req"), Size: 3},
		Response: model.HTTPMessage{
			Headers: []model.Header{{Name: "Content-Type", Value: "text/html; charset=utf-8"}},
			Body:    html,
			Size:    len(html),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	got := doReq(t, s.Handler(), http.MethodGet, "/v1/flows/"+res.ID+"/response", "")
	requireStatus(t, got, http.StatusOK)
	ct := got.Header().Get("Content-Type")
	if strings.Contains(ct, "text/html") {
		t.Fatalf("captured HTML type leaked onto management: %s", ct)
	}
	if !strings.Contains(ct, "application/octet-stream") {
		t.Fatalf("body type=%s", ct)
	}
	disp := got.Header().Get("Content-Disposition")
	wantName := `filename="flow-` + res.ID + `-response.bin"`
	if !strings.HasPrefix(disp, "attachment;") || !strings.Contains(disp, wantName) {
		t.Fatalf("disposition=%q", disp)
	}
	if got.Header().Get("Content-Security-Policy") != "default-src 'none'" {
		t.Fatalf("csp=%q", got.Header().Get("Content-Security-Policy"))
	}
	if got.Body.String() != string(html) {
		t.Fatalf("body=%q", got.Body.String())
	}
}

func TestUnauthenticatedIs401(t *testing.T) {
	s, _ := newTestServer(t)
	got := doReqAuth(t, s.Handler(), http.MethodGet, "/v1/flows", "", "")
	p := requireProblem(t, got, http.StatusUnauthorized, "unauthenticated")
	if p["type"] != "urn:labmitm:error:unauthenticated" {
		t.Fatalf("type=%v", p["type"])
	}
	if got.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate")
	}
}

func TestNilAuthIsDenyAll(t *testing.T) {
	svc := bootTestApp(t)
	s, err := New(Config{Service: svc, RatePerSec: -1})
	if err != nil {
		t.Fatal(err)
	}
	got := doReqAuth(t, s.Handler(), http.MethodGet, "/v1/flows", "", testToken)
	requireProblem(t, got, http.StatusUnauthorized, "unauthenticated")
}

func TestViewerForbiddenOnWriteAndAdmin(t *testing.T) {
	svc := bootTestApp(t)
	s, err := New(Config{
		Service:    svc,
		RatePerSec: -1,
		Auth:       auth.Static(testToken, "viewer", model.RoleViewer),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	id := insertFlow(t, svc, "app.lab")

	replay := doReq(t, h, http.MethodPost, "/v1/flows/"+id+":replay", "")
	requireProblem(t, replay, http.StatusForbidden, "forbidden")

	reset := doReq(t, h, http.MethodPost, "/v1/state:reset", `{"reason":"no"}`)
	requireProblem(t, reset, http.StatusForbidden, "forbidden")

	ca := doReq(t, h, http.MethodGet, "/v1/ca", "")
	requireStatus(t, ca, http.StatusOK)
	if strings.Contains(ca.Body.String(), "PRIVATE KEY") {
		t.Fatal("GET /v1/ca leaked a private key")
	}

	basic := httptestReq(http.MethodGet, "/v1/ca", "")
	basic.Header.Set("Authorization", "Basic YWRtaW46eA==")
	requireProblem(t, doRaw(h, basic), http.StatusUnauthorized, "unauthenticated")
}

func TestContractMutations(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	st := doReq(t, h, http.MethodGet, "/v1/state", "")
	rev := decodeJSON(t, st)["runtimeRevision"].(string)

	body, err := json.Marshal(map[string]any{
		"expectedRevision": rev,
		"reason":           "enable rules",
		"operations": []model.Operation{{
			Op:    model.OpReplaceRules,
			Rules: &model.RulesSpec{Enabled: true, Items: []model.RuleSpec{}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	val := doReq(t, h, http.MethodPost, "/v1/state:validate", `{"operations":[{"op":"replaceRules","rules":{"enabled":true,"items":[]}}]}`)
	requireStatus(t, val, http.StatusOK)

	plan := doReq(t, h, http.MethodPost, "/v1/changes:plan", string(body))
	requireStatus(t, plan, http.StatusOK)
	if decodeJSON(t, plan)["candidateRevision"] == rev {
		t.Fatal("plan did not change revision")
	}

	bad := doReq(t, h, http.MethodPost, "/v1/changes:apply", `{"expectedRevision":"sha256:deadbeef","operations":[{"op":"replaceRules","rules":{"enabled":true,"items":[]}}]}`)
	requireProblem(t, bad, http.StatusConflict, "revision_conflict")

	apply := doReq(t, h, http.MethodPost, "/v1/changes:apply", string(body))
	requireStatus(t, apply, http.StatusOK)
	if decodeJSON(t, apply)["applied"] != true {
		t.Fatalf("apply=%s", apply.Body.String())
	}

	exp := doReq(t, h, http.MethodGet, "/v1/state:export?format=yaml", "")
	requireStatus(t, exp, http.StatusOK)
	if !strings.Contains(exp.Header().Get("Content-Type"), "yaml") {
		t.Fatalf("export type=%s", exp.Header().Get("Content-Type"))
	}

	reset := doReq(t, h, http.MethodPost, "/v1/state:reset", `{"reason":"test"}`)
	requireStatus(t, reset, http.StatusOK)
}

func TestStoreOverNewCapCode(t *testing.T) {
	s, svc := newTestServer(t)
	h := s.Handler()
	insertFlow(t, svc, "one.lab")
	insertFlow(t, svc, "two.lab")
	rev := decodeJSON(t, doReq(t, h, http.MethodGet, "/v1/state", ""))["runtimeRevision"].(string)
	body, err := json.Marshal(map[string]any{
		"expectedRevision": rev,
		"operations": []map[string]any{{
			"op": "replaceStoreCaps",
			"store": map[string]any{
				"maxFlows":     1,
				"maxBytes":     "256MiB",
				"maxBodyBytes": "1MiB",
				"fullPolicy":   "reject",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := doReq(t, h, http.MethodPost, "/v1/changes:apply", string(body))
	p := requireProblem(t, got, http.StatusBadRequest, "store_over_new_cap")
	if p["code"] == "validation_failed" {
		t.Fatal("must not wrap store_over_new_cap")
	}
}

func TestWrongMethod(t *testing.T) {
	s, _ := newTestServer(t)
	got := doReq(t, s.Handler(), http.MethodPost, "/v1/health/live", "")
	requireProblem(t, got, http.StatusMethodNotAllowed, "method_not_allowed")
}

func TestWaitResumeDropReplay(t *testing.T) {
	s, svc := newTestServer(t)
	h := s.Handler()
	id := insertFlow(t, svc, "wait.lab")
	wait := doReq(t, h, http.MethodPost, "/v1/flows:wait", `{"filter":{"host":"wait.lab"},"timeout":"1s"}`)
	requireStatus(t, wait, http.StatusOK)

	if err := svc.Inbox().Pause(id); err != nil {
		t.Fatal(err)
	}
	resume := doReq(t, h, http.MethodPost, "/v1/flows/"+id+":resume", `{}`)
	requireStatus(t, resume, http.StatusNoContent)

	if err := svc.Inbox().Pause(id); err != nil && err != store.ErrBreakpointInactive {
		// completed flows cannot pause? Pause on completed is allowed in store.
		_ = err
	}
	// Pause a completed flow is ok per store.Pause.
	if err := svc.Inbox().Pause(id); err != nil {
		t.Fatal(err)
	}
	drop := doReq(t, h, http.MethodPost, "/v1/flows/"+id+":drop", "")
	requireStatus(t, drop, http.StatusNoContent)

	replay := doReq(t, h, http.MethodPost, "/v1/flows/"+id+":replay", "")
	requireStatus(t, replay, http.StatusOK)
	if decodeJSON(t, replay)["id"] == id {
		t.Fatal("replay must return a new flow id")
	}

	del := doReq(t, h, http.MethodDelete, "/v1/flows/"+id, "")
	requireStatus(t, del, http.StatusNoContent)

	clear := doReq(t, h, http.MethodDelete, "/v1/flows", "")
	requireStatus(t, clear, http.StatusOK)
}

func TestContractWebSocketFrames(t *testing.T) {
	s, svc := newTestServer(t)
	h := s.Handler()
	res, err := svc.Inbox().Insert(context.Background(), svc.Inbox().Epoch(), &model.Flow{
		Host:     "ws.lab",
		Method:   "GET",
		URL:      "http://ws.lab/ws",
		Scheme:   "http",
		Protocol: model.FlowProtocolWebSocket,
		State:    model.FlowStateCompleted,
		Status:   101,
		WebSocket: &model.WebSocketInfo{
			FrameCount: 1,
			Frames: []model.WebSocketFrame{{
				Direction: model.WSDirectionClient,
				Opcode:    "text",
				OpcodeNum: 1,
				Fin:       true,
				Masked:    true,
				Payload:   []byte("hello"),
				Size:      5,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := res.ID

	list := doReq(t, h, http.MethodGet, "/v1/flows?limit=1", "")
	requireStatus(t, list, http.StatusOK)
	items, _ := decodeJSON(t, list)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items=%s", list.Body.String())
	}
	ws, _ := items[0].(map[string]any)["websocket"].(map[string]any)
	if ws == nil {
		t.Fatalf("list missing websocket: %s", list.Body.String())
	}
	if _, ok := ws["frames"]; ok {
		t.Fatal("list item must omit frames")
	}
	if ws["frameCount"] != float64(1) {
		t.Fatalf("frameCount=%v", ws["frameCount"])
	}

	got := doReq(t, h, http.MethodGet, "/v1/flows/"+id, "")
	requireStatus(t, got, http.StatusOK)
	gws, _ := decodeJSON(t, got)["websocket"].(map[string]any)
	frames, _ := gws["frames"].([]any)
	if len(frames) != 1 {
		t.Fatalf("get frames=%s", got.Body.String())
	}
	fr := frames[0].(map[string]any)
	if fr["payload"] != "hello" {
		t.Fatalf("payload=%v (must be string, not base64)", fr["payload"])
	}
	if _, ok := fr["maskKey"]; ok {
		t.Fatal("maskKey must not be exported")
	}

	replay := doReq(t, h, http.MethodPost, "/v1/flows/"+id+":replay", "")
	requireProblem(t, replay, http.StatusBadRequest, "validation_failed")
}

func TestContractGRPC(t *testing.T) {
	s, svc := newTestServer(t)
	h := s.Handler()
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

	list := doReq(t, h, http.MethodGet, "/v1/flows?limit=1", "")
	requireStatus(t, list, http.StatusOK)
	items, _ := decodeJSON(t, list)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items=%s", list.Body.String())
	}
	g, _ := items[0].(map[string]any)["grpc"].(map[string]any)
	if g == nil {
		t.Fatalf("list missing grpc: %s", list.Body.String())
	}
	if _, ok := g["messages"]; ok {
		t.Fatal("list item must omit messages")
	}
	if g["contentType"] != "application/grpc" {
		t.Fatalf("contentType=%v", g["contentType"])
	}

	got := doReq(t, h, http.MethodGet, "/v1/flows/"+id, "")
	requireStatus(t, got, http.StatusOK)
	gg, _ := decodeJSON(t, got)["grpc"].(map[string]any)
	msgs, _ := gg["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("get messages=%s", got.Body.String())
	}
	fields, _ := msgs[0].(map[string]any)["fields"].([]any)
	if len(fields) != 1 || fields[0].(map[string]any)["text"] != "hi" {
		t.Fatalf("fields=%v", fields)
	}
}

func TestNoCORSHeaders(t *testing.T) {
	s, _ := newTestServer(t)
	got := doReq(t, s.Handler(), http.MethodOptions, "/v1/flows", "")
	requireProblem(t, got, http.StatusForbidden, "forbidden")
	if got.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS header present")
	}
}

func TestSessionCreateIsOK(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	got := doReq(t, h, http.MethodPost, "/v1/session", `{}`)
	requireStatus(t, got, http.StatusOK)
	m := decodeJSON(t, got)
	if m["csrf"] == "" || m["expiresAt"] == "" {
		t.Fatalf("session create=%s", got.Body.String())
	}
	requireStatus(t, doReq(t, h, http.MethodGet, "/v1/session", ""), http.StatusOK)
}

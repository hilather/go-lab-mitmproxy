package rest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDecodeRequestRejectsUnknownFields(t *testing.T) {
	s, _ := newTestServer(t)
	for _, tt := range []struct {
		body  string
		field string
	}{
		{`{"reasno":"oops"}`, "reasno"},
		{`{"operations":[{"op":"setFeature","feature":{"id":"rules.enabled","enabeld":true}}]}`, "enabeld"},
		{`{"operations":[{"op":"replaceAdmission","admission":{"maxSesion":3}}]}`, "maxSesion"},
	} {
		t.Run(tt.field, func(t *testing.T) {
			rec := httptest.NewRecorder()
			var in changeRequest
			req := httptest.NewRequest(http.MethodPost, "/v1/changes:plan", strings.NewReader(tt.body))
			if s.decodeBytes(rec, req, "test", []byte(tt.body), &in) {
				t.Fatal("unknown field accepted")
			}
			requireRequestViolation(t, rec, "unknown fields", tt.field, "unknown_field", `unknown field "`+tt.field+`"`)
		})
	}
}

func TestRESTResetDecodeErrors(t *testing.T) {
	for _, tt := range []struct {
		name, body, detail, path, code, message string
	}{
		{
			name: "unknown field", body: `{"reason":"x","nope":true}`,
			detail: "unknown fields", path: "nope", code: "unknown_field", message: `unknown field "nope"`,
		},
		{
			name: "escaped unknown field", body: `{"reason":"x","odd\"key":"do-not-expose"}`,
			detail: "unknown fields", path: `odd"key`, code: "unknown_field", message: `unknown field "odd\"key"`,
		},
		{
			name: "malformed JSON", body: `{"reason":]}`,
			detail: "invalid JSON", code: "invalid_value", message: "request body is not valid JSON",
		},
		{
			name: "trailing JSON", body: `{"reason":"x"} {}`,
			detail: "request body must contain a single JSON value", code: "invalid_value", message: "trailing JSON is not allowed",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, svc := newTestServer(t)
			id := insertFlow(t, svc, "app.lab")
			epoch := svc.Inbox().Epoch()
			rec := doReq(t, s.Handler(), http.MethodPost, "/v1/state:reset", tt.body)
			requireRequestViolation(t, rec, tt.detail, tt.path, tt.code, tt.message)
			if strings.Contains(rec.Body.String(), "do-not-expose") {
				t.Fatal("decode error exposed the unknown field value")
			}
			if svc.Inbox().Epoch() != epoch {
				t.Fatal("rejected request reset the store")
			}
			if _, err := svc.Inbox().Get(id); err != nil {
				t.Fatalf("rejected request removed a flow: %v", err)
			}
		})
	}
}

func requireRequestViolation(t *testing.T, rec *httptest.ResponseRecorder, detail, path, code, message string) {
	t.Helper()
	problem := requireProblem(t, rec, http.StatusBadRequest, "validation_failed")
	if problem["detail"] != detail {
		t.Fatalf("detail=%v want %q; body=%s", problem["detail"], detail, rec.Body.String())
	}
	violations, ok := problem["fieldViolations"].([]any)
	if !ok || len(violations) != 1 {
		t.Fatalf("expected one field violation: %s", rec.Body.String())
	}
	violation, ok := violations[0].(map[string]any)
	if !ok || violation["path"] != path || violation["code"] != code || violation["message"] != message {
		t.Fatalf("violation=%v want path=%q code=%q message=%q", violations[0], path, code, message)
	}
}

func TestDecodeCandidateStateCoercesUnitsOnce(t *testing.T) {
	s, _ := newTestServer(t)
	body := `{"state":{"apiVersion":"labmitm.dev/v1alpha1","kind":"LabMITM","metadata":{"name":"test"},"spec":{"store":{"maxBytes":"8MiB"},"proxy":{"admission":{"headerTimeout":"3s"}}}}}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/state:validate", strings.NewReader(body))
	var in changeRequest
	if !s.decodeBytes(rec, req, "test", []byte(body), &in) {
		t.Fatalf("decode: %s", rec.Body.String())
	}
	st, err := decodeCandidateState(in.State)
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.Store.MaxBytes != 8*1024*1024 || st.Spec.Proxy.Admission.HeaderTimeout != 3*time.Second {
		t.Fatalf("units: %+v", st.Spec)
	}
}

func TestRESTUnknownOperationDoesNotMutateState(t *testing.T) {
	s, _ := newTestServer(t)
	state := decodeJSON(t, doReq(t, s.Handler(), http.MethodGet, "/v1/state", ""))
	revision := state["runtimeRevision"].(string)
	body := `{"expectedRevision":"` + revision + `","idempotencyKey":"unknown-feature","reason":"test","operations":[{"op":"setFeature","feature":{"id":"ui.enabled","enabeld":true}}]}`
	rec := doReq(t, s.Handler(), http.MethodPost, "/v1/changes:apply", body)
	requireStatus(t, rec, http.StatusBadRequest)
	after := decodeJSON(t, doReq(t, s.Handler(), http.MethodGet, "/v1/state", ""))
	if after["runtimeRevision"] != revision {
		t.Fatal("rejected request mutated state")
	}
}

func TestDecodeOperationUnitsOnce(t *testing.T) {
	s, _ := newTestServer(t)
	body := `{"operations":[{"op":"replaceAdmission","admission":{"headerTimeout":"3s","maxInFlightBytes":"8MiB"}}]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/changes:plan", strings.NewReader(body))
	var in changeRequest
	if !s.decodeBytes(rec, req, "test", []byte(body), &in) {
		t.Fatalf("decode: %s", rec.Body.String())
	}
	ad := in.Operations[0].Admission
	if ad.HeaderTimeout != 3*time.Second || ad.MaxInFlightBytes != 8*1024*1024 {
		t.Fatalf("units: %+v", ad)
	}
}

func TestRESTValidateCandidateUnitStrings(t *testing.T) {
	s, _ := newTestServer(t)
	body := `{"state":{"apiVersion":"labmitm.dev/v1alpha1","kind":"LabMITM","metadata":{"name":"test"},"spec":{"store":{"maxBytes":"8MiB"},"proxy":{"admission":{"headerTimeout":"3s"}}}}}`
	rec := doReq(t, s.Handler(), http.MethodPost, "/v1/state:validate", body)
	requireStatus(t, rec, http.StatusOK)
	out := decodeJSON(t, rec)
	if revision, ok := out["candidateRevision"].(string); !ok || revision == "" {
		t.Fatalf("validation: %s", rec.Body.String())
	}
}

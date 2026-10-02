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
	for _, body := range []string{
		`{"reasno":"oops"}`,
		`{"operations":[{"op":"setFeature","feature":{"id":"rules.enabled","enabeld":true}}]}`,
		`{"operations":[{"op":"replaceAdmission","admission":{"maxSesion":3}}]}`,
	} {
		t.Run(body, func(t *testing.T) {
			rec := httptest.NewRecorder()
			var in changeRequest
			req := httptest.NewRequest(http.MethodPost, "/v1/changes:plan", strings.NewReader(body))
			if s.decodeBytes(rec, req, "test", []byte(body), &in) {
				t.Fatal("unknown field accepted")
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
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

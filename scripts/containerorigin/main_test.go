package main

import (
	"net/http/httptest"
	"testing"
)

func TestFixtureBodies(t *testing.T) {
	for _, secure := range []bool{false, true} {
		rec := httptest.NewRecorder()
		fixtureHandler(secure).ServeHTTP(rec, httptest.NewRequest("GET", "/container-smoke", nil))
		want := "container-smoke"
		if secure {
			want += "-https"
		}
		if rec.Code != 200 || rec.Body.String() != want {
			t.Fatalf("secure=%v status=%d body=%q", secure, rec.Code, rec.Body.String())
		}
	}
}
func TestInvalidTLSFailsBeforeBinding(t *testing.T) {
	if err := serveOrigins("/missing-cert", "/missing-key"); err == nil {
		t.Fatal("invalid TLS fixture started")
	}
}

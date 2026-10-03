package proxy

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

func TestBreakpointResumeExplicitEmptyBodyOnWire(t *testing.T) {
	for _, phase := range []string{model.RulePhaseRequest, model.RulePhaseResponse} {
		t.Run(phase, func(t *testing.T) {
			originBody := make(chan string, 1)
			_, originURL := startOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				originBody <- string(body)
				_, _ = io.WriteString(w, "original-response")
			}))
			spec := withRules(t, model.RuleSpec{ID: "empty-resume", Enabled: true, Phase: phase, Match: model.RuleMatchSpec{PathPrefix: "/empty"}, Action: model.RuleActionSpec{Type: model.ActionBreakpoint, Breakpoint: model.RuleBreakpointSpec{Timeout: 5 * time.Second}}})
			inbox := newProxyStore(t, store.Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: time.Minute})
			px := startProxy(t, Options{Spec: spec, Sink: AdaptStore(inbox), Store: inbox})
			done := make(chan *http.Response, 1)
			go func() {
				done <- proxyDo(t, px.Addr().String(), http.MethodPost, originURL+"/empty", "original-request")
			}()
			paused := waitFlow(t, inbox, model.FlowFilter{PathPrefix: "/empty"})
			if err := inbox.Resume(paused.ID, &store.ResumePatch{Body: []byte{}}); err != nil {
				t.Fatal(err)
			}
			select {
			case resp := <-done:
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				want := "original-response"
				if phase == model.RulePhaseResponse {
					want = ""
				}
				if string(body) != want {
					t.Fatalf("client body %q want %q", body, want)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("resume did not finish")
			}
			received := <-originBody
			want := "original-request"
			if phase == model.RulePhaseRequest {
				want = ""
			}
			if received != want {
				t.Fatalf("origin request body %q want %q", received, want)
			}
		})
	}
}

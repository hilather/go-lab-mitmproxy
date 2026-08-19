package app

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/proxy"
)

func startLiveProxy(t *testing.T, svc *App) *proxy.Server {
	t.Helper()
	snap := svc.Active()
	srv, err := proxy.New(proxy.Options{
		Address:   "127.0.0.1:0",
		Spec:      snap.Canonical.Spec,
		Sink:      proxy.AdaptStore(svc.Inbox()),
		Store:     svc.Inbox(),
		Snapshots: svc.Snapshots(),
		Authority: snap.CA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("proxy did not bind")
	}
	return srv
}

func startLiveOrigin(t *testing.T, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var proto http.Protocols
	proto.SetHTTP1(true)
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		Protocols:         &proto,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return "http://" + ln.Addr().String()
}

func viaProxy(t *testing.T, proxyAddr, target string) *http.Response {
	t.Helper()
	tr := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse("http://" + proxyAddr)
		},
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestApplyReplaceRulesLiveOnNextRequest(t *testing.T) {
	svc, boot := mustBoot(t)
	var hits int
	origin := startLiveOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = io.WriteString(w, "ok")
	}))
	px := startLiveProxy(t, svc)
	resp := viaProxy(t, px.Addr().String(), origin+"/x")
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("before apply status=%d body=%q", resp.StatusCode, body)
	}
	if hits != 1 {
		t.Fatalf("hits=%d", hits)
	}

	_, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Reason:           "drop all",
		Operations: []model.Operation{{
			Op: model.OpReplaceRules,
			Rules: &model.RulesSpec{
				Enabled: true,
				Items: []model.RuleSpec{{
					ID:      "drop-all",
					Enabled: true,
					Phase:   model.RulePhaseRequest,
					Action:  model.RuleActionSpec{Type: model.ActionDrop, Status: 403},
				}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp = viaProxy(t, px.Addr().String(), origin+"/x")
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("after apply status=%d", resp.StatusCode)
	}
	if hits != 1 {
		t.Fatalf("drop must not dial origin; hits=%d", hits)
	}
}

func TestInFlightRequestKeepsPinnedSnapshot(t *testing.T) {
	svc, boot := mustBoot(t)
	started := make(chan struct{})
	release := make(chan struct{})
	origin := startLiveOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(started)
			<-release
		}
		_, _ = io.WriteString(w, "slow")
	}))
	px := startLiveProxy(t, svc)

	var wg sync.WaitGroup
	wg.Add(1)
	var firstStatus int
	var firstBody string
	go func() {
		defer wg.Done()
		resp := viaProxy(t, px.Addr().String(), origin+"/slow")
		firstStatus = resp.StatusCode
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		firstBody = string(b)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("origin never saw in-flight request")
	}

	// Response-phase drop would rewrite this hop if it reloaded the live snapshot.
	_, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Operations: []model.Operation{{
			Op: model.OpReplaceRules,
			Rules: &model.RulesSpec{
				Enabled: true,
				Items: []model.RuleSpec{{
					ID:      "drop-resp",
					Enabled: true,
					Phase:   model.RulePhaseResponse,
					Action:  model.RuleActionSpec{Type: model.ActionDrop, Status: 403},
				}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	wg.Wait()
	if firstStatus != 200 || firstBody != "slow" {
		t.Fatalf("in-flight hop must keep the pinned engine, status=%d body=%q", firstStatus, firstBody)
	}

	resp := viaProxy(t, px.Addr().String(), origin+"/next")
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("next request should see response drop, status=%d", resp.StatusCode)
	}
}

func TestResetDiscardsInFlightCapture(t *testing.T) {
	svc, _ := mustBoot(t)
	insertRaw(t, svc, "already.lab")
	started := make(chan struct{})
	release := make(chan struct{})
	origin := startLiveOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/inflight" {
			close(started)
			<-release
		}
		_, _ = io.WriteString(w, "ok")
	}))
	px := startLiveProxy(t, svc)

	var wg sync.WaitGroup
	wg.Add(1)
	var status int
	go func() {
		defer wg.Done()
		resp := viaProxy(t, px.Addr().String(), origin+"/inflight")
		status = resp.StatusCode
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("origin never saw in-flight request")
	}

	if _, err := svc.Reset(context.Background(), actor(), ResetIn{Reason: "wipe mid-hop"}); err != nil {
		t.Fatal(err)
	}
	close(release)
	wg.Wait()
	if status != 200 {
		t.Fatalf("in-flight hop must still forward, status=%d", status)
	}
	if svc.Inbox().Stats().FlowCount != 0 {
		t.Fatalf("stale-epoch capture must not refill inbox, count=%d", svc.Inbox().Stats().FlowCount)
	}

	resp := viaProxy(t, px.Addr().String(), origin+"/after")
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("post-reset request status=%d", resp.StatusCode)
	}
	if svc.Inbox().Stats().FlowCount != 1 {
		t.Fatalf("new request should insert, count=%d", svc.Inbox().Stats().FlowCount)
	}
}

func TestReplaceTargetsLiveOnNextRequest(t *testing.T) {
	svc, boot := mustBoot(t)
	origin := startLiveOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	px := startLiveProxy(t, svc)
	resp := viaProxy(t, px.Addr().String(), origin+"/")
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("before targets status=%d", resp.StatusCode)
	}

	tg := boot.Canonical.Spec.Proxy.Targets
	// Literal IPs skip allowHosts/denyHosts globs; deny loopback to
	// reject the 127.0.0.1 origin on the next request.
	tg.AllowLoopback = false
	_, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Operations:       []model.Operation{{Op: model.OpReplaceTargets, Targets: &tg}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp = viaProxy(t, px.Addr().String(), origin+"/")
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("after replaceTargets status=%d", resp.StatusCode)
	}
}

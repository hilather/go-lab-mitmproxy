package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/proxy"
)

type liveResolver map[string][]net.IP

func (m liveResolver) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	if addrs, ok := m[host]; ok {
		out := make([]net.IP, len(addrs))
		copy(out, addrs)
		return out, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func startLiveProxy(t *testing.T, svc *App) *proxy.Server {
	t.Helper()
	return startLiveProxyWith(t, svc, proxy.Options{})
}

func startLiveProxyWith(t *testing.T, svc *App, extra proxy.Options) *proxy.Server {
	t.Helper()
	snap := svc.Active()
	opts := extra
	if opts.Address == "" {
		opts.Address = "127.0.0.1:0"
	}
	opts.Spec = snap.Canonical.Spec
	if opts.Sink == nil {
		opts.Sink = proxy.AdaptStore(svc.Inbox())
	}
	if opts.Store == nil {
		opts.Store = svc.Inbox()
	}
	opts.Snapshots = svc.Snapshots()
	if opts.Authority == nil {
		opts.Authority = snap.CA
	}
	srv, err := proxy.New(opts)
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

func TestInFlightRequestKeepsPinnedSnapshotSilent(t *testing.T) {
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
	first, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Operations: []model.Operation{{
			Op: model.OpReplaceRules,
			Rules: &model.RulesSpec{
				Enabled: true,
				Items: []model.RuleSpec{{
					ID:      "delay-slow",
					Enabled: true,
					Phase:   model.RulePhaseRequest,
					Match:   model.RuleMatchSpec{PathPrefix: "/slow"},
					Action:  model.RuleActionSpec{Type: model.ActionDelay, Delay: 40 * time.Millisecond},
				}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
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
		t.Fatal("origin never saw in-flight delayed request")
	}

	_, err = svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: first.RuntimeRevision,
		Operations: []model.Operation{{
			Op: model.OpReplaceRules,
			Rules: &model.RulesSpec{
				Enabled: true,
				Items: []model.RuleSpec{{
					ID:      "silent-all",
					Enabled: true,
					Phase:   model.RulePhaseRequest,
					Action:  model.RuleActionSpec{Type: model.ActionSilent},
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
		t.Fatalf("in-flight delay must keep the pinned engine, status=%d body=%q", firstStatus, firstBody)
	}

	tr := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse("http://" + px.Addr().String())
		},
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
	}
	req, err := http.NewRequest(http.MethodGet, origin+"/next", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err == nil {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("next request must hit silent RST, got status %d", resp.StatusCode)
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

func TestApplySOCKS5LiveWithoutRestart(t *testing.T) {
	svc, boot := mustBoot(t)
	origin := startLiveOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "socks-ok")
	}))
	px := startLiveProxy(t, svc)

	closed := socksDial(t, px.Addr().String())
	if _, err := closed.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	_ = closed.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8)
	n, err := closed.Read(buf)
	if err == nil && n >= 2 && buf[0] == 0x05 && buf[1] == 0x00 {
		t.Fatal("SOCKS5 must stay closed while acceptSOCKS5 is off")
	}
	_ = closed.Close()

	_, err = svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		IdempotencyKey:   "live-socks5-on",
		Operations:       []model.Operation{setFeatureOp(FeatureIDAcceptSOCKS5, true)},
	})
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("origin host %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	c := socksDial(t, px.Addr().String())
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	greet := readLiveN(t, c, 2)
	if greet[0] != 0x05 || greet[1] != 0x00 {
		t.Fatalf("greeting %x", greet)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := readLiveN(t, c, 10)
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("connect reply %x", reply)
	}
	if _, err := io.WriteString(c, "GET /hello HTTP/1.1\r\nHost: "+u.Host+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "socks-ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}

	offRev := svc.Active().Revision
	_, err = svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: offRev,
		IdempotencyKey:   "live-socks5-off",
		Operations:       []model.Operation{setFeatureOp(FeatureIDAcceptSOCKS5, false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	closed2 := socksDial(t, px.Addr().String())
	defer func() { _ = closed2.Close() }()
	if _, err := closed2.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	_ = closed2.SetDeadline(time.Now().Add(2 * time.Second))
	n, err = closed2.Read(buf)
	if err == nil && n >= 2 && buf[0] == 0x05 && buf[1] == 0x00 {
		t.Fatal("next 0x05 must close after apply-off")
	}
}

func TestApplyHTTP2LiveNewCONNECTALPN(t *testing.T) {
	svc, boot := mustBoot(t)
	origin := startLiveTLSOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	_, port := liveHostPort(t, origin)
	rev := applyLiveIntercept(t, svc, boot.Revision, port)
	px := startLiveProxyWith(t, svc, proxy.Options{Resolver: liveResolver{"app.lab": {net.ParseIP("127.0.0.1")}}})

	alpn := liveCONNECTALPN(t, px, port, []string{"h2", "http/1.1"})
	if alpn != "http/1.1" {
		t.Fatalf("before apply ALPN=%q", alpn)
	}

	_, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: rev,
		IdempotencyKey:   "live-http2-on",
		Operations:       []model.Operation{setFeatureOp(FeatureIDHTTP2, true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	alpn = liveCONNECTALPN(t, px, port, []string{"h2", "http/1.1"})
	if alpn != "h2" {
		t.Fatalf("after apply ALPN=%q", alpn)
	}
}

func TestApplyWebsocketOffInnerPinThenNewCONNECT(t *testing.T) {
	svc, boot := mustBoot(t)
	var upgrades, gets atomic.Int32
	origin := startLiveTLSOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			upgrades.Add(1)
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", 500)
				return
			}
			c, bufrw, err := hj.Hijack()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_ = bufrw.Flush()
			_, _ = io.Copy(io.Discard, bufrw)
			return
		}
		gets.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	_, port := liveHostPort(t, origin)
	rev := applyLiveIntercept(t, svc, boot.Revision, port)
	px := startLiveProxyWith(t, svc, proxy.Options{Resolver: liveResolver{"app.lab": {net.ParseIP("127.0.0.1")}}})

	pinned := liveInnerTLS(t, px, port)
	defer func() { _ = pinned.Close() }()

	_, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: rev,
		IdempotencyKey:   "live-ws-off",
		Operations:       []model.Operation{setFeatureOp(FeatureIDWebSocket, false)},
	})
	if err != nil {
		t.Fatal(err)
	}

	wsReq, _ := http.NewRequest(http.MethodGet, "https://app.lab/ws", nil)
	wsReq.Header.Set("Upgrade", "websocket")
	wsReq.Header.Set("Connection", "Upgrade")
	wsReq.Header.Set("Sec-WebSocket-Version", "13")
	wsReq.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if err := wsReq.Write(pinned); err != nil {
		t.Fatal(err)
	}
	pinnedBR := bufio.NewReader(pinned)
	wsResp, err := http.ReadResponse(pinnedBR, wsReq)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(wsResp.Body)
	_ = wsResp.Body.Close()
	if wsResp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("pinned CONNECT inner upgrade status %d", wsResp.StatusCode)
	}
	if upgrades.Load() != 1 {
		t.Fatalf("pinned upgrade origin hits=%d", upgrades.Load())
	}

	fresh := liveInnerTLS(t, px, port)
	defer func() { _ = fresh.Close() }()
	wsReq2, _ := http.NewRequest(http.MethodGet, "https://app.lab/ws", nil)
	wsReq2.Header.Set("Upgrade", "websocket")
	wsReq2.Header.Set("Connection", "Upgrade")
	wsReq2.Header.Set("Sec-WebSocket-Version", "13")
	wsReq2.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if err := wsReq2.Write(fresh); err != nil {
		t.Fatal(err)
	}
	freshBR := bufio.NewReader(fresh)
	offResp, err := http.ReadResponse(freshBR, wsReq2)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(offResp.Body)
	_ = offResp.Body.Close()
	if offResp.StatusCode != http.StatusForbidden {
		t.Fatalf("new CONNECT inner upgrade status %d", offResp.StatusCode)
	}
	if offResp.Header.Get("Connection") == "close" || offResp.Close {
		t.Fatal("inner 403 must not send Connection: close")
	}
	if upgrades.Load() != 1 {
		t.Fatalf("disabled upgrade invoked origin; hits=%d", upgrades.Load())
	}

	get, _ := http.NewRequest(http.MethodGet, "https://app.lab/ok", nil)
	if err := get.Write(fresh); err != nil {
		t.Fatal(err)
	}
	getResp, err := http.ReadResponse(freshBR, get)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(getResp.Body)
	_ = getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("follow-up GET status %d body %q", getResp.StatusCode, body)
	}
	if gets.Load() != 1 {
		t.Fatalf("follow-up GET origin hits=%d", gets.Load())
	}
}

func TestApplyWebsocketOffCleartextNextRequest(t *testing.T) {
	svc, boot := mustBoot(t)
	var hits atomic.Int32
	origin := startLiveOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", 500)
			return
		}
		c, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = bufrw.Flush()
	}))
	px := startLiveProxy(t, svc)
	first := liveCleartextUpgrade(t, px.Addr().String(), origin)
	if first != http.StatusSwitchingProtocols {
		t.Fatalf("default websocket status %d", first)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits=%d", hits.Load())
	}
	_, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		IdempotencyKey:   "live-ws-cleartext-off",
		Operations:       []model.Operation{setFeatureOp(FeatureIDWebSocket, false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	second := liveCleartextUpgrade(t, px.Addr().String(), origin)
	if second != http.StatusForbidden {
		t.Fatalf("after apply status %d", second)
	}
	if hits.Load() != 1 {
		t.Fatalf("disabled upgrade dialed origin; hits=%d", hits.Load())
	}
}

func startLiveTLSOrigin(t *testing.T, h http.Handler) string {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(repoRoot(t), "testdata", "tls", "origin.pem"),
		filepath.Join(repoRoot(t), "testdata", "tls", "origin-key.pem"),
	)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	var proto http.Protocols
	proto.SetHTTP1(true)
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		Protocols:         &proto,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	go func() { _ = srv.Serve(tlsLn) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	})
	return ln.Addr().String()
}

func applyLiveIntercept(t *testing.T, svc *App, rev model.Revision, originPort int) model.Revision {
	t.Helper()
	tlsSpec := svc.Active().Canonical.Spec.TLS
	tlsSpec.Intercept = true
	tlsSpec.Ports = []int{originPort}
	tlsSpec.Upstream.ExtraCAFiles = []string{filepath.Join(repoRoot(t), "testdata", "tls", "origin-ca.pem")}
	res, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: rev,
		IdempotencyKey:   "live-intercept-" + strconv.Itoa(originPort),
		Operations:       []model.Operation{{Op: model.OpReplaceTLS, TLS: &tlsSpec}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.RuntimeRevision
}

func liveHostPort(t *testing.T, addr string) (host string, port int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := net.LookupPort("tcp", p)
	if err != nil {
		t.Fatal(err)
	}
	return h, n
}

func liveCONNECTALPN(t *testing.T, px *proxy.Server, originPort int, nextProtos []string) string {
	t.Helper()
	tlsConn := liveInnerTLSConfig(t, px, originPort, nextProtos)
	defer func() { _ = tlsConn.Close() }()
	return tlsConn.ConnectionState().NegotiatedProtocol
}

func liveInnerTLS(t *testing.T, px *proxy.Server, originPort int) *tls.Conn {
	t.Helper()
	return liveInnerTLSConfig(t, px, originPort, []string{"http/1.1"})
}

func liveInnerTLSConfig(t *testing.T, px *proxy.Server, originPort int, nextProtos []string) *tls.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", px.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	target := net.JoinHostPort("app.lab", strconv.Itoa(originPort))
	if _, err := io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	st, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if st != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatalf("CONNECT status %q", st)
	}
	if blank, err := br.ReadString('\n'); err != nil || blank != "\r\n" {
		t.Fatalf("CONNECT blank %q err=%v", blank, err)
	}
	if leftover := br.Buffered(); leftover != 0 {
		t.Fatalf("CONNECT leftover %d", leftover)
	}
	tlsConn := tls.Client(c, &tls.Config{
		ServerName: "app.lab",
		RootCAs:    px.Authority().CertPool(),
		NextProtos: nextProtos,
		MinVersion: tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tlsConn
}

func liveCleartextUpgrade(t *testing.T, proxyAddr, origin string) int {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	raw := "GET " + origin + "/ws HTTP/1.1\r\nHost: " + origin[len("http://"):] + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func socksDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

func readLiveN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	p := make([]byte, n)
	if _, err := io.ReadFull(c, p); err != nil {
		t.Fatal(err)
	}
	return p
}

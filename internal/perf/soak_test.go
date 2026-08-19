package perf

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/proxy"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

// defaultSoakN is small so CI stays short. This is completeness under
// accept/wait/wipe, not a QPS gate. Local lab target: 100 flows/s for 30s.
const defaultSoakN = 8

var soakNFlag = flag.Int("soak-n", defaultSoakN, "flows to accept during soak (CI default 8)")

func soakN(t *testing.T) int {
	t.Helper()
	n := *soakNFlag
	if env := os.Getenv("LABMITM_SOAK_N"); env != "" {
		parsed, err := strconv.Atoi(env)
		if err != nil {
			t.Fatalf("LABMITM_SOAK_N: %v", err)
		}
		n = parsed
	}
	if testing.Short() && n > 2 {
		n = 2
	}
	if n < 1 {
		n = 1
	}
	return n
}

func TestSoakAcceptWaitWipe(t *testing.T) {
	n := soakN(t)
	inbox := newInbox(t, n)
	_, originURL := startOrigin(t)
	px := startProxy(t, inbox)

	for i := 0; i < n; i++ {
		path := fmt.Sprintf("/soak-%d", i)
		if got := throughProxy(t, px.Addr().String(), originURL+path); got != "ok-"+path {
			t.Fatalf("accept %d: body %q", i, got)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := inbox.Wait(ctx, model.FlowFilter{PathPrefix: fmt.Sprintf("/soak-%d", n-1)})
	if err != nil {
		t.Fatalf("wait last: %v", err)
	}
	if got == nil || got.Path() != fmt.Sprintf("/soak-%d", n-1) {
		t.Fatalf("wait last = %+v", got)
	}

	st := inbox.Stats()
	if st.FlowCount != n {
		t.Fatalf("flow count %d want %d", st.FlowCount, n)
	}
	epoch := inbox.Epoch()
	gen := inbox.Generation()

	inbox.Wipe()
	after := inbox.Stats()
	if after.FlowCount != 0 || after.Bytes != 0 {
		t.Fatalf("wipe left occupancy count=%d bytes=%d", after.FlowCount, after.Bytes)
	}
	if inbox.Epoch() == epoch {
		t.Fatal("wipe did not bump epoch")
	}
	if inbox.Generation() == gen {
		t.Fatal("wipe did not bump storeGeneration")
	}

	// Wait after wipe must not resurrect deleted flows.
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer waitCancel()
	resurrected, err := inbox.Wait(waitCtx, model.FlowFilter{})
	if resurrected != nil {
		t.Fatalf("wait after wipe returned %s", resurrected.ID)
	}
	if err == nil {
		t.Fatal("wait after wipe succeeded")
	}
}

func TestSoakWaitThenAcceptThenWipe(t *testing.T) {
	n := soakN(t)
	inbox := newInbox(t, n)
	_, originURL := startOrigin(t)
	px := startProxy(t, inbox)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		got, err := inbox.Wait(ctx, model.FlowFilter{PathPrefix: "/soak-parked"})
		if err != nil {
			errc <- err
			return
		}
		if got == nil {
			errc <- fmt.Errorf("wait returned nil")
			return
		}
		errc <- nil
	}()

	// Let the waiter park on the cond before the first insert.
	time.Sleep(20 * time.Millisecond)
	for i := 0; i < n; i++ {
		path := fmt.Sprintf("/soak-parked-%d", i)
		if got := throughProxy(t, px.Addr().String(), originURL+path); got != "ok-"+path {
			t.Fatalf("accept %d: body %q", i, got)
		}
	}

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("parked wait: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("parked wait did not return")
	}

	if inbox.Stats().FlowCount != n {
		t.Fatalf("flow count %d want %d", inbox.Stats().FlowCount, n)
	}
	inbox.Wipe()
	if inbox.Stats().FlowCount != 0 {
		t.Fatal("wipe left flows")
	}
}

func newInbox(t *testing.T, n int) *store.Memory {
	t.Helper()
	inbox, err := store.New(store.Options{
		MaxFlows:   n + 8,
		MaxBytes:   16 << 20,
		FullPolicy: model.FullPolicyReject,
		MaxWait:    5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inbox.Wipe)
	return inbox
}

func startProxy(t *testing.T, inbox *store.Memory) *proxy.Server {
	t.Helper()
	st, err := config.Load([]byte("apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: soak\nspec: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := proxy.New(proxy.Options{
		Address: "127.0.0.1:0",
		Spec:    st.Spec,
		Sink:    proxy.AdaptStore(inbox),
		Store:   inbox,
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

func startOrigin(t *testing.T) (addr, urlstr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var proto http.Protocols
	proto.SetHTTP1(true)
	proto.SetHTTP2(false)
	proto.SetUnencryptedHTTP2(false)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "ok-"+r.URL.Path)
		}),
		ReadHeaderTimeout: 5 * time.Second,
		Protocols:         &proto,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	})
	addr = ln.Addr().String()
	return addr, "http://" + addr
}

func throughProxy(t *testing.T, proxyAddr, target string) string {
	t.Helper()
	u, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{
		Proxy:             http.ProxyURL(u),
		ForceAttemptHTTP2: false,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %q", resp.StatusCode, b)
	}
	return string(b)
}

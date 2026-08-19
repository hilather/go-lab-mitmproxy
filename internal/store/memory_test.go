package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestMemoryInsertULIDAndStats(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	res, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://app.lab.test/a", 200, []byte("hi")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ulid.Parse(res.ID); err != nil || len(res.ID) != 26 {
		t.Fatalf("id=%q err=%v", res.ID, err)
	}
	got, err := s.Get(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Method != "GET" || !bytes.Equal(got.Response.Body, []byte("hi")) {
		t.Fatalf("got %+v", got)
	}
	st := s.Stats()
	if st.FlowCount != 1 || st.Bytes != got.ResidentBytes() || st.Generation != res.Generation {
		t.Fatalf("stats=%+v resident=%d", st, got.ResidentBytes())
	}
}

func TestMemoryRejectFull(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 1, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	if _, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/a", 200, []byte("one"))); err != nil {
		t.Fatal(err)
	}
	_, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/b", 200, []byte("two")))
	if !errors.Is(err, ErrFull) {
		t.Fatalf("err=%v", err)
	}
	if s.Stats().FlowCount != 1 {
		t.Fatalf("count=%d", s.Stats().FlowCount)
	}
}

func TestMemoryTooLarge(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 32, FullPolicy: model.FullPolicyEvictOldest})
	_, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/", 200, []byte(strings.Repeat("x", 200))))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err=%v", err)
	}
	if s.Stats().FlowCount != 0 {
		t.Fatal("evicted inbox on oversized flow")
	}
}

func TestMemoryTruncateMaxBodyBytes(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, MaxBodyBytes: 4, FullPolicy: model.FullPolicyReject})
	res, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("POST", "http://h/", 200, []byte("12345678")))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || !got.Response.Truncated || string(got.Response.Body) != "1234" {
		t.Fatalf("truncate %+v body=%q", got, got.Response.Body)
	}
}

func TestMemoryEvictOldest(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 2, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyEvictOldest})
	a, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/a", 200, []byte("1")))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	b, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/b", 200, []byte("2")))
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/c", 200, []byte("3")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest still present: %v", err)
	}
	if _, err := s.Get(b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(c.ID); err != nil {
		t.Fatal(err)
	}
	if s.Stats().Evictions != 1 {
		t.Fatalf("evictions=%d", s.Stats().Evictions)
	}
}

func TestMemoryWipeStaleInsert(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	old := s.Epoch()
	if _, err := s.Insert(context.Background(), old, sampleFlow("GET", "http://h/", 200, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	if s.Epoch() == old {
		t.Fatal("epoch not bumped")
	}
	if s.Stats().FlowCount != 0 {
		t.Fatal("wipe left flows")
	}
	_, err := s.Insert(context.Background(), old, sampleFlow("GET", "http://h/", 200, []byte("y")))
	if !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("err=%v", err)
	}
	if s.Stats().FlowCount != 0 {
		t.Fatal("stale insert stored")
	}
}

func TestMemoryWaitTimeout(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := s.Wait(ctx, model.FlowFilter{Host: "nope"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
}

func TestMemoryWaitWakes(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: 2 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		got, err := s.Wait(ctx, model.FlowFilter{Host: "wake.lab"})
		if err != nil {
			errc <- err
			return
		}
		if got.Host != "wake.lab" {
			errc <- errors.New(got.Host)
			return
		}
		errc <- nil
	}()
	time.Sleep(15 * time.Millisecond)
	if _, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://wake.lab/", 200, []byte("n"))); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not wake")
	}
}

func TestMemoryWaitDoesNotReturnDeleted(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject, MaxWait: 2 * time.Second})
	res, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://gone.lab/", 200, []byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(res.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	got, err := s.Wait(ctx, model.FlowFilter{Host: "gone.lab"})
	if got != nil {
		t.Fatalf("returned deleted %s", got.ID)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
}

func TestMemoryDeleteAllDoesNotBumpEpoch(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	ep := s.Epoch()
	if _, err := s.Insert(context.Background(), ep, sampleFlow("GET", "http://h/", 200, []byte("y"))); err != nil {
		t.Fatal(err)
	}
	g := s.Generation()
	n, err := s.DeleteAll()
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if s.Epoch() != ep {
		t.Fatalf("epoch %d -> %d", ep, s.Epoch())
	}
	if s.Generation() <= g {
		t.Fatalf("generation did not move: %d -> %d", g, s.Generation())
	}
}

func TestMemoryListFilter(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	a := sampleFlow("GET", "http://app.lab.test/login", 200, []byte("a"))
	a.Intercepted = true
	b := sampleFlow("POST", "http://other.lab/x", 404, []byte("b"))
	if _, err := s.Insert(context.Background(), s.Epoch(), a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Insert(context.Background(), s.Epoch(), b); err != nil {
		t.Fatal(err)
	}
	yes := true
	list, err := s.List(model.ListQuery{Filter: model.FlowFilter{Host: "app.lab.test", Method: "GET", PathPrefix: "/login", Status: 200, Intercepted: &yes}})
	if err != nil || len(list.Items) != 1 || list.Items[0].Host != "app.lab.test" {
		t.Fatalf("filter=%+v err=%v", list, err)
	}
}

func TestMemoryListAndDelete(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	_, _ = s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/one", 200, []byte("a")))
	time.Sleep(2 * time.Millisecond)
	b, _ := s.Insert(context.Background(), s.Epoch(), sampleFlow("POST", "http://h/two", 201, []byte("b")))
	list, err := s.List(model.ListQuery{Limit: 1})
	if err != nil || len(list.Items) != 1 || list.Items[0].Method != "POST" || list.NextCursor == "" {
		t.Fatalf("list=%+v err=%v", list, err)
	}
	page2, err := s.List(model.ListQuery{Limit: 1, Cursor: list.NextCursor})
	if err != nil || len(page2.Items) != 1 || page2.Items[0].Method != "GET" {
		t.Fatalf("page2=%+v err=%v", page2, err)
	}
	if err := s.Delete("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing delete %v", err)
	}
	if err := s.Delete(b.ID); err != nil {
		t.Fatal(err)
	}
	n, err := s.DeleteAll()
	if err != nil || n != 1 {
		t.Fatalf("deleteAll n=%d err=%v", n, err)
	}
	if s.Stats().FlowCount != 0 {
		t.Fatal("not empty")
	}
}

func TestMemorySpillRoundTripAndWipe(t *testing.T) {
	dir := t.TempDir()
	s := newTestStore(t, Options{
		MaxFlows:       10,
		MaxBytes:       1 << 20,
		FullPolicy:     model.FullPolicyReject,
		SpillDirectory: dir,
		SpillThreshold: 8,
	})
	body := []byte(strings.Repeat("z", 40))
	res, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/spill", 200, body))
	if err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) == 0 {
		t.Fatal("expected spill file")
	}
	got, err := s.Get(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Response.Body, body) {
		t.Fatalf("body after spill len=%d want %d", len(got.Response.Body), len(body))
	}
	s.Wipe()
	ents, _ = os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".body") {
			t.Fatalf("spill remained %s", e.Name())
		}
	}
}

func TestMemoryStartupWipesSpill(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "01HZYXWV7TSRQPJMKN76543210-req.body")
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = newTestStore(t, Options{
		MaxFlows:       10,
		MaxBytes:       1024,
		SpillDirectory: dir,
		SpillThreshold: 1,
	})
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale spill remained: %v", err)
	}
}

func TestMemoryEvictOldestSpillFailureKeepsOld(t *testing.T) {
	dir := t.TempDir()
	s := newTestStore(t, Options{
		MaxFlows:       1,
		MaxBytes:       1 << 20,
		FullPolicy:     model.FullPolicyEvictOldest,
		SpillDirectory: dir,
		SpillThreshold: 8,
	})
	first, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/keep", 200, []byte(strings.Repeat("a", 40))))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, err = s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/new", 200, []byte(strings.Repeat("b", 40))))
	if err == nil {
		t.Fatal("expected spill failure")
	}
	if !errors.Is(err, ErrSpill) {
		t.Fatalf("err=%v", err)
	}
	if s.Stats().Evictions != 0 {
		t.Fatalf("evictions=%d", s.Stats().Evictions)
	}
	got, err := s.Get(first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "h" || !strings.Contains(got.URL, "/keep") {
		t.Fatalf("url=%q", got.URL)
	}
}

func TestMemoryListAfterWipeOldCursorIsEmpty(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	old, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/old", 200, []byte("a")))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	if _, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/new", 200, []byte("b"))); err != nil {
		t.Fatal(err)
	}
	page, err := s.List(model.ListQuery{Cursor: old.ID, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("wipe+old cursor replayed %v", idsOf(page))
	}
}

func TestMemoryGetUnreadableSpill(t *testing.T) {
	dir := t.TempDir()
	s := newTestStore(t, Options{
		MaxFlows:       10,
		MaxBytes:       1 << 20,
		FullPolicy:     model.FullPolicyReject,
		SpillDirectory: dir,
		SpillThreshold: 8,
	})
	body := []byte(strings.Repeat("z", 40))
	res, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/spill", 200, body))
	if err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) == 0 {
		t.Fatalf("spill files: %v %v", ents, err)
	}
	for _, e := range ents {
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
	_, err = s.Get(res.ID)
	if !errors.Is(err, ErrSpill) {
		t.Fatalf("get err=%v", err)
	}
}

func TestNewFailsIfSpillCannotClear(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "01HZYXWV7TSRQPJMKN76543210-resp.body")
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	_, err := New(Options{
		MaxFlows:       10,
		MaxBytes:       1024,
		SpillDirectory: dir,
		SpillThreshold: 1,
	})
	if !errors.Is(err, ErrSpill) {
		t.Fatalf("err=%v", err)
	}
}

func TestMemoryInsertCanceled(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1024, FullPolicy: model.FullPolicyReject})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Insert(ctx, s.Epoch(), sampleFlow("GET", "http://h/", 200, []byte("y")))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestReplaceCapsRejectOverWithoutForce(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	if _, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/a", 200, []byte("one"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/b", 200, []byte("two"))); err != nil {
		t.Fatal(err)
	}
	err := s.ReplaceCaps(Options{MaxFlows: 1, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject}, false)
	if !errors.Is(err, ErrOverNewCap) {
		t.Fatalf("err=%v", err)
	}
	if s.Stats().FlowCount != 2 {
		t.Fatal("reject shrink must not evict")
	}
}

func TestReplaceCapsForceEvictsOldest(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	first, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/a", 200, []byte("one")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/b", 200, []byte("two"))); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceCaps(Options{MaxFlows: 1, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject}, true); err != nil {
		t.Fatal(err)
	}
	st := s.Stats()
	if st.FlowCount != 1 {
		t.Fatalf("count=%d", st.FlowCount)
	}
	if _, err := s.Get(first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest should be evicted: %v", err)
	}
}

func TestReplaceCapsEvictOldestPolicy(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	if _, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/a", 200, []byte("one"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://h/b", 200, []byte("two"))); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceCaps(Options{MaxFlows: 1, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyEvictOldest}, false); err != nil {
		t.Fatal(err)
	}
	if s.Stats().FlowCount != 1 {
		t.Fatalf("count=%d", s.Stats().FlowCount)
	}
}

func TestResetToWipesAndInstallsCaps(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	old := s.Epoch()
	if _, err := s.Insert(context.Background(), old, sampleFlow("GET", "http://h/", 200, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetTo(Options{MaxFlows: 2, MaxBytes: 4096, FullPolicy: model.FullPolicyEvictOldest}); err != nil {
		t.Fatal(err)
	}
	if s.Epoch() == old || s.Stats().FlowCount != 0 {
		t.Fatalf("reset leftover epoch=%d count=%d", s.Epoch(), s.Stats().FlowCount)
	}
	if _, err := s.Insert(context.Background(), old, sampleFlow("GET", "http://h/", 200, []byte("stale"))); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("stale after reset: %v", err)
	}
}

func TestCheckOptionsBadSpill(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := CheckOptions(Options{
		MaxFlows:       1,
		MaxBytes:       1024,
		FullPolicy:     model.FullPolicyReject,
		SpillDirectory: filepath.Join(blocker, "spill"),
	})
	if err == nil {
		t.Fatal("expected spill mkdir failure")
	}
}

func TestNewRejectsBadCaps(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("empty options")
	}
	if _, err := New(Options{MaxFlows: 1, MaxBytes: 10, FullPolicy: "drop"}); err == nil {
		t.Fatal("bad policy")
	}
}

func TestSentinelTooLargeAndNotFound(t *testing.T) {
	if errors.Is(ErrTooLarge, ErrFull) || errors.Is(ErrNotFound, ErrStaleEpoch) {
		t.Fatal("sentinels must differ")
	}
}

func TestGoldenHTTPFlow(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	f := loadGolden(t, "http-get.json")
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "app.lab.test" || got.Status != 200 || string(got.Response.Body) != "ok" {
		t.Fatalf("golden %+v", got)
	}
}

func TestGoldenHTTPSIntercept(t *testing.T) {
	s := newTestStore(t, Options{MaxFlows: 10, MaxBytes: 1 << 20, FullPolicy: model.FullPolicyReject})
	f := loadGolden(t, "https-intercept.json")
	res, err := s.Insert(context.Background(), s.Epoch(), f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Intercepted || got.TLS == nil || got.TLS.SNI != "app.lab.test" || !got.TLS.UpstreamVerified {
		t.Fatalf("tls %+v", got.TLS)
	}
}

func loadGolden(t *testing.T, name string) *model.Flow {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "flows", name))
	if err != nil {
		t.Fatal(err)
	}
	var f model.Flow
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

func idsOf(r model.ListResult) []string {
	out := make([]string, len(r.Items))
	for i, m := range r.Items {
		out[i] = m.ID
	}
	return out
}

func newTestStore(t *testing.T, opts Options) *Memory {
	t.Helper()
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Wipe)
	return s
}

func sampleFlow(method, rawURL string, status int, body []byte) *model.Flow {
	host := "h"
	if u := rawURL; strings.Contains(u, "://") {
		rest := u[strings.Index(u, "://")+3:]
		if i := strings.IndexAny(rest, "/?"); i >= 0 {
			host = rest[:i]
		} else {
			host = rest
		}
	}
	return &model.Flow{
		StartedAt: time.Now().UTC(),
		State:     model.FlowStateCompleted,
		Method:    method,
		URL:       rawURL,
		Host:      host,
		Scheme:    "http",
		Protocol:  model.FlowProtocolHTTP11,
		Status:    status,
		Response:  model.HTTPMessage{Body: append([]byte(nil), body...), Size: len(body)},
	}
}

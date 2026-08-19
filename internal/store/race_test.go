package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestRaceInsertDeleteWaitWipe(t *testing.T) {
	s := newTestStore(t, Options{
		MaxFlows:   200,
		MaxBytes:   8 << 20,
		FullPolicy: model.FullPolicyEvictOldest,
		MaxWait:    50 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				res, err := s.Insert(context.Background(), s.Epoch(), sampleFlow("GET", "http://race.lab/", 200, []byte("x")))
				if err != nil {
					continue
				}
				_, _ = s.Get(res.ID)
				_, _ = s.List(model.ListQuery{Limit: 10})
				_ = s.Delete(res.ID)
				wctx, wcancel := context.WithTimeout(ctx, 5*time.Millisecond)
				_, _ = s.Wait(wctx, model.FlowFilter{Host: "race.lab"})
				wcancel()
				if j%11 == 0 {
					_, _ = s.DeleteAll()
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 8; i++ {
			time.Sleep(2 * time.Millisecond)
			s.Wipe()
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 8; i++ {
			time.Sleep(3 * time.Millisecond)
			_ = s.ReplaceCaps(Options{MaxFlows: 200, MaxBytes: 8 << 20, FullPolicy: model.FullPolicyEvictOldest}, false)
			if i%2 == 0 {
				_ = s.ResetTo(Options{MaxFlows: 200, MaxBytes: 8 << 20, FullPolicy: model.FullPolicyEvictOldest, MaxWait: 50 * time.Millisecond})
			}
		}
	}()
	wg.Wait()
}

func TestRaceBreakpointResumeDrop(t *testing.T) {
	s := newTestStore(t, Options{
		MaxFlows:   200,
		MaxBytes:   8 << 20,
		FullPolicy: model.FullPolicyEvictOldest,
	})
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				f := sampleFlow("GET", "http://bp.lab/", 0, []byte("p"))
				f.State = model.FlowStatePaused
				res, err := s.Insert(context.Background(), s.Epoch(), f)
				if err != nil {
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				done := make(chan struct{})
				go func(id string) {
					_, _ = s.WaitPaused(ctx, id)
					close(done)
				}(res.ID)
				if j%2 == 0 {
					_ = s.Resume(res.ID, &ResumePatch{Body: []byte("r")})
				} else {
					_ = s.Drop(res.ID)
				}
				<-done
				cancel()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 6; i++ {
			time.Sleep(3 * time.Millisecond)
			s.Wipe()
		}
	}()
	wg.Wait()
}

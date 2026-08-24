package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/observability"
)

const defaultMaxBodyBytes = int64(1 << 20)

var _ Store = (*Memory)(nil)

// Memory is a process-local, mutex-protected flow inbox.
type Memory struct {
	maxFlows       int
	maxBytes       int64
	maxBodyBytes   int64
	fullPolicy     string
	maxWait        time.Duration
	spillDir       string
	spillThreshold int64

	mu         sync.Mutex
	cond       *sync.Cond
	epoch      uint64
	generation uint64
	evictions  uint64
	bytes      int64
	byID       map[string]*record
	order      []string
	subs       []*subscriber
	waiters    int
	paused     map[string][]*pauseWaiter
	metrics    *observability.Registry
	logger     *observability.Logger
}

type record struct {
	flow        *model.Flow
	resident    int64
	reqSpill    string
	respSpill   string
	wsSpill     string
	wasPaused   bool
	pauseDone   bool
	pauseResult pauseResult
}

type recSnap struct {
	flow      *model.Flow
	reqSpill  string
	respSpill string
	wsSpill   string
}

func normalizeOptions(opts Options) (Options, error) {
	if opts.MaxFlows <= 0 {
		return opts, errors.New("store: maxFlows must be > 0")
	}
	if opts.MaxBytes <= 0 {
		return opts, errors.New("store: maxBytes must be > 0")
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = defaultMaxBodyBytes
	}
	switch opts.FullPolicy {
	case "", model.FullPolicyReject:
		opts.FullPolicy = model.FullPolicyReject
	case model.FullPolicyEvictOldest:
	default:
		return opts, fmt.Errorf("store: unknown fullPolicy %q", opts.FullPolicy)
	}
	if opts.SpillDirectory != "" && opts.SpillThreshold <= 0 {
		opts.SpillThreshold = 256 << 10
	}
	return opts, nil
}

// New builds an empty inbox and wipes any leftover spill files.
func New(opts Options) (*Memory, error) {
	opts, err := normalizeOptions(opts)
	if err != nil {
		return nil, err
	}
	m := &Memory{
		maxFlows:       opts.MaxFlows,
		maxBytes:       opts.MaxBytes,
		maxBodyBytes:   opts.MaxBodyBytes,
		fullPolicy:     opts.FullPolicy,
		maxWait:        opts.MaxWait,
		spillDir:       opts.SpillDirectory,
		spillThreshold: opts.SpillThreshold,
		epoch:          1,
		byID:           make(map[string]*record),
		paused:         make(map[string][]*pauseWaiter),
	}
	m.cond = sync.NewCond(&m.mu)
	if err := m.prepareSpill(); err != nil {
		return nil, err
	}
	return m, nil
}

// SetTelemetry attaches optional metrics and slog events. Nil is a no-op.
func (m *Memory) SetTelemetry(r *observability.Registry, l *observability.Logger) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics = r
	m.logger = l
	m.publishLocked()
}

func (m *Memory) publishLocked() {
	if m.metrics == nil {
		return
	}
	m.metrics.Set(observability.MetricStoreFlows, nil, float64(len(m.byID)))
	m.metrics.Set(observability.MetricStoreBytes, nil, float64(m.bytes))
	m.metrics.Set(observability.MetricStoreWaiters, nil, float64(m.waiters))
}

func (m *Memory) logStore(rec observability.Record) {
	if m == nil || m.logger == nil || rec.Event == "" {
		return
	}
	m.logger.Log(rec)
}

// CheckOptions validates caps and creates the spill directory when set.
// It does not unlink files and does not mutate an inbox.
func CheckOptions(opts Options) (Options, error) {
	opts, err := normalizeOptions(opts)
	if err != nil {
		return opts, err
	}
	if err := ensureSpillDir(opts.SpillDirectory); err != nil {
		return opts, err
	}
	return opts, nil
}

func (m *Memory) prepareSpill() error {
	if err := ensureSpillDir(m.spillDir); err != nil {
		return err
	}
	if m.spillDir == "" {
		return nil
	}
	return m.unlinkAllSpill()
}

func applyBodyCaps(f *model.Flow, max int64) {
	if f == nil || max <= 0 {
		return
	}
	if truncateSide(&f.Request, max) {
		f.Truncated = true
	}
	if truncateSide(&f.Response, max) {
		f.Truncated = true
	}
	if truncateWebSocket(f.WebSocket, max) {
		f.Truncated = true
	}
	if truncateGRPC(f.GRPC, max) {
		f.Truncated = true
	}
}

func truncateWebSocket(ws *model.WebSocketInfo, max int64) bool {
	if ws == nil || max <= 0 {
		return false
	}
	truncated := ws.Truncated
	if len(ws.Frames) > model.WSMaxFrames {
		ws.Frames = ws.Frames[:model.WSMaxFrames]
		ws.Truncated = true
		truncated = true
	}
	var used int64
	for i := range ws.Frames {
		p := ws.Frames[i].Payload
		remain := max - used
		if remain <= 0 {
			ws.Frames = ws.Frames[:i]
			ws.Truncated = true
			return true
		}
		if int64(len(p)) > remain {
			ws.Frames[i].Payload = append([]byte(nil), p[:remain]...)
			ws.Frames[i].Truncated = true
			ws.Frames[i].Size = len(ws.Frames[i].Payload)
			ws.Frames = ws.Frames[:i+1]
			ws.Truncated = true
			return true
		}
		used += int64(len(p))
		if ws.Frames[i].Size == 0 {
			ws.Frames[i].Size = len(p)
		}
	}
	return truncated
}

func truncateGRPC(g *model.GRPCInfo, max int64) bool {
	if g == nil || max <= 0 {
		return false
	}
	truncated := g.Truncated
	for g.TreeBytes() > max && len(g.Messages) > 0 {
		last := &g.Messages[len(g.Messages)-1]
		if len(last.Fields) > 0 {
			last.Fields = last.Fields[:len(last.Fields)-1]
		} else {
			g.Messages = g.Messages[:len(g.Messages)-1]
		}
		g.Truncated = true
		truncated = true
		if g.DecodeError == "" {
			g.DecodeError = model.GRPCDecodeTruncated
		}
	}
	return truncated
}

func truncateSide(msg *model.HTTPMessage, max int64) bool {
	if int64(len(msg.Body)) > max {
		msg.Body = append([]byte(nil), msg.Body[:max]...)
		msg.Truncated = true
	}
	if msg.Size == 0 {
		msg.Size = len(msg.Body)
	} else if int64(msg.Size) > max && len(msg.Body) > 0 {
		msg.Size = len(msg.Body)
		msg.Truncated = true
	}
	return msg.Truncated
}

// Insert assigns a ULID, applies maxBodyBytes, and charges resident bytes.
func (m *Memory) Insert(ctx context.Context, epoch uint64, f *model.Flow) (model.InsertResult, error) {
	if m == nil {
		return model.InsertResult{}, errors.New("store: nil Memory")
	}
	if err := ctx.Err(); err != nil {
		return model.InsertResult{}, err
	}
	if f == nil {
		return model.InsertResult{}, errors.New("store: nil flow")
	}

	prepared := cloneFlow(f)
	if prepared.StartedAt.IsZero() {
		prepared.StartedAt = time.Now().UTC()
	}
	if prepared.State == "" {
		prepared.State = model.FlowStateCompleted
	}
	if prepared.CompletedAt.IsZero() && prepared.State != model.FlowStatePaused && prepared.State != model.FlowStateOpen {
		prepared.CompletedAt = time.Now().UTC()
	}
	id := ulid.Make().String()
	prepared.ID = id

	m.mu.Lock()
	maxBody := m.maxBodyBytes
	maxBytes := m.maxBytes
	spillDir := m.spillDir
	spillTh := m.spillThreshold
	m.mu.Unlock()

	applyBodyCaps(prepared, maxBody)
	candidate := prepared.ResidentBytes()
	if candidate > maxBytes {
		return model.InsertResult{}, ErrTooLarge
	}

	// Spill to temp names before taking the index lock so a write failure
	// cannot evict existing flows. Rename + evict + index happen atomically.
	job, err := writeSpillTemps(spillDir, spillTh, prepared)
	if err != nil {
		return model.InsertResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			unlinkSpillJob(job)
		}
	}()

	var recLog, pausedLog observability.Record
	m.mu.Lock()
	defer func() {
		m.mu.Unlock()
		m.logStore(recLog)
		m.logStore(pausedLog)
	}()
	if epoch != m.epoch {
		return model.InsertResult{}, ErrStaleEpoch
	}
	if err := m.canAcceptLocked(candidate); err != nil {
		if errors.Is(err, ErrFull) {
			if m.metrics != nil {
				m.metrics.Inc(observability.MetricStoreFullTotal, nil, 1)
			}
			recLog = observability.Record{Event: observability.EventStoreFull, Component: "store", Result: "store_full"}
		}
		return model.InsertResult{}, err
	}
	rec := &record{flow: prepared, resident: candidate, wasPaused: prepared.State == model.FlowStatePaused}
	if err := commitSpill(rec, job); err != nil {
		return model.InsertResult{}, err
	}
	if err := m.evictUntilFitsLocked(candidate); err != nil {
		unlinkRecord(rec)
		return model.InsertResult{}, err
	}
	m.byID[id] = rec
	m.insertOrderLocked(id, prepared.EvictTime())
	m.bytes += candidate
	m.generation++
	m.cond.Broadcast()
	kind := EventInserted
	if prepared.State == model.FlowStatePaused {
		kind = EventPaused
	}
	m.emitLocked(Event{Kind: kind, ID: id, Host: prepared.Host, Gen: m.generation})
	m.publishLocked()
	recLog = observability.Record{
		Event:           observability.EventStoreInserted,
		Component:       "store",
		FlowID:          id,
		Host:            prepared.Host,
		Result:          "ok",
		StoreGeneration: m.generation,
	}
	if prepared.State == model.FlowStatePaused {
		pausedLog = observability.Record{
			Event:           observability.EventFlowPaused,
			Component:       "store",
			FlowID:          id,
			Host:            prepared.Host,
			Result:          "paused",
			StoreGeneration: m.generation,
		}
	}
	committed = true
	return model.InsertResult{ID: id, Generation: m.generation}, nil
}

func (m *Memory) fitsLocked(candidate int64) bool {
	return len(m.byID) < m.maxFlows && m.bytes+candidate <= m.maxBytes
}

func (m *Memory) canAcceptLocked(candidate int64) error {
	if m.fitsLocked(candidate) {
		return nil
	}
	if m.fullPolicy != model.FullPolicyEvictOldest {
		return ErrFull
	}
	bytes := m.bytes
	count := len(m.byID)
	for _, id := range m.order {
		if count < m.maxFlows && bytes+candidate <= m.maxBytes {
			return nil
		}
		rec := m.byID[id]
		if rec == nil {
			continue
		}
		bytes -= rec.resident
		if bytes < 0 {
			bytes = 0
		}
		count--
	}
	if count < m.maxFlows && bytes+candidate <= m.maxBytes {
		return nil
	}
	return ErrFull
}

func (m *Memory) evictUntilFitsLocked(candidate int64) error {
	for len(m.order) > 0 && !m.fitsLocked(candidate) {
		m.removeLocked(m.order[0], true)
	}
	if !m.fitsLocked(candidate) {
		return ErrFull
	}
	return nil
}

// evictOthersUntilFitsLocked frees extra bytes without removing keepID.
func (m *Memory) evictOthersUntilFitsLocked(keepID string, extra int64) error {
	if extra < 0 {
		extra = 0
	}
	for m.bytes+extra > m.maxBytes {
		victim := ""
		for _, id := range m.order {
			if id != keepID {
				victim = id
				break
			}
		}
		if victim == "" {
			break
		}
		m.removeLocked(victim, true)
	}
	if m.bytes+extra > m.maxBytes {
		return ErrFull
	}
	return nil
}

func (m *Memory) occupancyOKLocked() bool {
	return len(m.byID) <= m.maxFlows && m.bytes <= m.maxBytes
}

func (m *Memory) evictUntilUnderCapsLocked() error {
	for len(m.order) > 0 && !m.occupancyOKLocked() {
		m.removeLocked(m.order[0], true)
	}
	if !m.occupancyOKLocked() {
		return ErrOverNewCap
	}
	return nil
}

func (m *Memory) insertOrderLocked(id string, at time.Time) {
	pos := len(m.order)
	for i, oid := range m.order {
		other := m.byID[oid]
		if other == nil {
			continue
		}
		ot := other.flow.EvictTime()
		if at.Before(ot) || (at.Equal(ot) && id < oid) {
			pos = i
			break
		}
	}
	m.order = append(m.order, "")
	copy(m.order[pos+1:], m.order[pos:])
	m.order[pos] = id
}

// Get returns a clone. Spill is loaded after releasing the index lock.
func (m *Memory) Get(id string) (*model.Flow, error) {
	m.mu.Lock()
	rec, ok := m.byID[id]
	if !ok {
		m.mu.Unlock()
		return nil, ErrNotFound
	}
	snap := snapshotRecord(rec)
	m.mu.Unlock()
	if err := loadSpill(snap); err != nil {
		if os.IsNotExist(err) {
			m.mu.Lock()
			_, still := m.byID[id]
			m.mu.Unlock()
			if !still {
				return nil, ErrNotFound
			}
		}
		return nil, fmt.Errorf("%w: %v", ErrSpill, err)
	}
	return snap.flow, nil
}

// List returns newest-first pages. Cursor is the last id from the previous page.
func (m *Memory) List(q model.ListQuery) (model.ListResult, error) {
	m.mu.Lock()
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultListLimit
	}
	if limit > MaxListLimit {
		limit = MaxListLimit
	}
	cur, fresh := m.resolveCursorLocked(q.Cursor)
	passed := q.Cursor == "" || fresh
	var snaps []recSnap
	var lastID string
	var next string
	for i := len(m.order) - 1; i >= 0; i-- {
		id := m.order[i]
		rec := m.byID[id]
		if rec == nil {
			continue
		}
		if !passed {
			if cur.found && id == cur.id {
				passed = true
				continue
			}
			if !cur.found && !newerThanCursor(rec.flow, cur) {
				passed = true
			} else {
				continue
			}
		}
		if !matchFilter(rec.flow, q.Filter) {
			continue
		}
		if len(snaps) == limit {
			next = lastID
			break
		}
		snaps = append(snaps, snapshotRecord(rec))
		lastID = id
	}
	gen := m.generation
	m.mu.Unlock()

	items := make([]*model.Flow, 0, len(snaps))
	for _, snap := range snaps {
		if err := loadSpill(snap); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return model.ListResult{}, fmt.Errorf("%w: %v", ErrSpill, err)
		}
		items = append(items, snap.flow)
	}
	return model.ListResult{Items: items, NextCursor: next, Generation: gen}, nil
}

type cursorPos struct {
	id    string
	at    time.Time
	found bool
}

func (m *Memory) resolveCursorLocked(id string) (cursorPos, bool) {
	if id == "" {
		return cursorPos{}, true
	}
	if rec, ok := m.byID[id]; ok {
		return cursorPos{id: id, at: rec.flow.EvictTime(), found: true}, false
	}
	u, err := ulid.Parse(id)
	if err != nil {
		return cursorPos{id: id}, false
	}
	return cursorPos{id: id, at: ulid.Time(u.Time())}, false
}

func newerThanCursor(f *model.Flow, cur cursorPos) bool {
	at := f.EvictTime()
	if at.After(cur.at) {
		return true
	}
	if at.Equal(cur.at) && f.ID > cur.id {
		return true
	}
	return false
}

// Delete removes one flow.
func (m *Memory) Delete(id string) error {
	m.mu.Lock()
	if _, ok := m.byID[id]; !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	m.removeLocked(id, false)
	m.publishLocked()
	recLog := observability.Record{
		Event:           observability.EventStoreDeleted,
		Component:       "store",
		FlowID:          id,
		StoreGeneration: m.generation,
	}
	m.mu.Unlock()
	m.logStore(recLog)
	return nil
}

// DeleteAll empties the inbox without bumping epoch.
func (m *Memory) DeleteAll() (int, error) {
	m.mu.Lock()
	n := len(m.byID)
	if n == 0 {
		m.mu.Unlock()
		return 0, nil
	}
	ids := append([]string(nil), m.order...)
	for _, id := range ids {
		m.removeLocked(id, false)
	}
	m.mu.Unlock()
	return n, nil
}

// Wait returns the newest matching flow or ctx/maxWait timeout.
func (m *Memory) Wait(ctx context.Context, filter model.FlowFilter) (*model.Flow, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	maxWait := m.maxWait
	m.mu.Unlock()
	if maxWait > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, maxWait)
		defer cancel()
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			m.cond.Broadcast()
			m.mu.Unlock()
		case <-stop:
		}
	}()

	m.mu.Lock()
	for {
		if rec := m.newestMatchLocked(filter); rec != nil {
			snap := snapshotRecord(rec)
			m.mu.Unlock()
			if err := loadSpill(snap); err != nil {
				if os.IsNotExist(err) {
					m.mu.Lock()
					_, still := m.byID[snap.flow.ID]
					if still {
						m.mu.Unlock()
						return nil, fmt.Errorf("%w: %v", ErrSpill, err)
					}
					continue
				}
				return nil, fmt.Errorf("%w: %v", ErrSpill, err)
			}
			return snap.flow, nil
		}
		if err := ctx.Err(); err != nil {
			m.mu.Unlock()
			return nil, err
		}
		m.waiters++
		m.publishLocked()
		m.cond.Wait()
		m.waiters--
		if m.waiters < 0 {
			m.waiters = 0
		}
		m.publishLocked()
	}
}

func (m *Memory) newestMatchLocked(filter model.FlowFilter) *record {
	for i := len(m.order) - 1; i >= 0; i-- {
		rec := m.byID[m.order[i]]
		if rec != nil && matchFilter(rec.flow, filter) {
			return rec
		}
	}
	return nil
}

// Generation increments on insert, delete, wipe, evict, and breakpoint state.
func (m *Memory) Generation() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generation
}

// Epoch is captured at request start; Wipe/ResetTo are the only bumps.
func (m *Memory) Epoch() uint64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.epoch
}

// Stats is occupancy plus counters.
func (m *Memory) Stats() model.StoreStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return model.StoreStats{
		FlowCount:  len(m.byID),
		Bytes:      m.bytes,
		Generation: m.generation,
		Epoch:      m.epoch,
		Evictions:  m.evictions,
	}
}

// ReplaceCaps applies the replaceStoreCaps fields.
func (m *Memory) ReplaceCaps(opts Options, force bool) error {
	if m == nil {
		return errors.New("store: nil Memory")
	}
	opts, err := normalizeOptions(opts)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	over := len(m.byID) > opts.MaxFlows || m.bytes > opts.MaxBytes
	if over && opts.FullPolicy != model.FullPolicyEvictOldest && !force {
		return ErrOverNewCap
	}
	m.maxFlows = opts.MaxFlows
	m.maxBytes = opts.MaxBytes
	m.maxBodyBytes = opts.MaxBodyBytes
	m.fullPolicy = opts.FullPolicy
	if over {
		if err := m.evictUntilUnderCapsLocked(); err != nil {
			return ErrOverNewCap
		}
	}
	return nil
}

// ResetTo wipes the inbox and installs opts under one lock so Insert cannot
// land between Wipe and the new caps. Callers must CheckOptions first.
func (m *Memory) ResetTo(opts Options) error {
	if m == nil {
		return errors.New("store: nil Memory")
	}
	opts, err := normalizeOptions(opts)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.failPausedLocked(ErrStaleEpoch)
	m.epoch++
	m.generation++
	m.byID = make(map[string]*record)
	m.order = nil
	m.bytes = 0
	_ = m.unlinkAllSpill()
	m.maxFlows = opts.MaxFlows
	m.maxBytes = opts.MaxBytes
	m.maxBodyBytes = opts.MaxBodyBytes
	m.fullPolicy = opts.FullPolicy
	m.maxWait = opts.MaxWait
	m.spillDir = opts.SpillDirectory
	m.spillThreshold = opts.SpillThreshold
	m.cond.Broadcast()
	m.emitLocked(Event{Kind: EventWiped, Gen: m.generation})
	m.publishLocked()
	recLog := observability.Record{
		Event:           observability.EventStoreWiped,
		Component:       "store",
		StoreGeneration: m.generation,
	}
	m.mu.Unlock()
	m.logStore(recLog)
	return nil
}

// Wipe increments epoch, empties the index, unlinks spill, and cancels waiters.
func (m *Memory) Wipe() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.failPausedLocked(ErrStaleEpoch)
	m.epoch++
	m.generation++
	m.byID = make(map[string]*record)
	m.order = nil
	m.bytes = 0
	_ = m.unlinkAllSpill()
	m.cond.Broadcast()
	m.emitLocked(Event{Kind: EventWiped, Gen: m.generation})
	m.publishLocked()
	recLog := observability.Record{
		Event:           observability.EventStoreWiped,
		Component:       "store",
		StoreGeneration: m.generation,
	}
	m.mu.Unlock()
	m.logStore(recLog)
}

func (m *Memory) removeLocked(id string, eviction bool) {
	rec, ok := m.byID[id]
	if !ok {
		return
	}
	delete(m.byID, id)
	for i, oid := range m.order {
		if oid == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	m.bytes -= rec.resident
	if m.bytes < 0 {
		m.bytes = 0
	}
	unlinkRecord(rec)
	m.generation++
	if eviction {
		m.evictions++
		if m.metrics != nil {
			m.metrics.Inc(observability.MetricStoreEvictions, nil, 1)
		}
	}
	m.finishPausedLocked(id, pauseResult{err: ErrNotFound})
	m.cond.Broadcast()
	host := ""
	if rec.flow != nil {
		host = rec.flow.Host
	}
	m.emitLocked(Event{Kind: EventDeleted, ID: id, Host: host, Gen: m.generation})
}

func snapshotRecord(rec *record) recSnap {
	return recSnap{
		flow:      cloneFlow(rec.flow),
		reqSpill:  rec.reqSpill,
		respSpill: rec.respSpill,
		wsSpill:   rec.wsSpill,
	}
}

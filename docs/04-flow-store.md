# Flow Store

Status: Proposed normative behavior
Owners: Store, Proxy, Application
Last reviewed: 2026-08-23 (D67 WebSocket frames)
Related ADRs: 0003, 0012

Package `internal/store`. Captured HTTP is runtime evidence, not desired state. Restart or reset wipes flows. Pattern is LabMail `docs/03-message-store.md`. SOCKS metadata may include `SOCKSInfo.User` as the matching YAML `userPass` id after RFC 1929 success; username and password are never stored on the flow.

STORE-001 implements `store.Memory` (ULID ids via `github.com/oklog/ulid/v2`, stacked caps, Wait, Wipe epoch, Pause/Resume/Drop/WaitPaused, optional spill). STA-001 pins the store epoch on the proxy session at accept (`beginSession`). Completed and paused inserts use that epoch; a mismatch under the insert lock returns `store.ErrStaleEpoch` and the flow is not stored, so reset leaves the inbox empty even if an in-flight hop still forwards. `fullPolicy: reject` returns `store.ErrFull`; the proxy **still forwards** (capture is best-effort). A single flow whose resident size exceeds `maxBytes` returns `store.ErrTooLarge`. Bodies larger than `maxBodyBytes` are truncated and flagged. `store.Null` remains a discard Sink for tests. `labmitm serve` constructs Memory from `spec.store` and `Wipe`s on process shutdown.

## Interface

```go
type ResumePatch struct {
    Headers []Header // optional replacement; nil = keep
    Body    []byte   // optional; nil = keep; must be ≤ maxBodyBytes
}

type Event struct {
    Kind string // inserted | paused | resumed | dropped | deleted | wiped
    ID   string
    Gen  uint64
}

type Store interface {
    Insert(ctx context.Context, epoch uint64, f *model.Flow) (model.InsertResult, error)
    Get(id string) (*model.Flow, error)
    List(model.ListQuery) (model.ListResult, error)
    Delete(id string) error
    DeleteAll() (deleted int, err error)
    Wait(ctx context.Context, filter model.FlowFilter) (*model.Flow, error)
    Pause(id string) error
    Resume(id string, patch *ResumePatch) error
    Drop(id string) error
    WaitPaused(ctx context.Context, id string) (ResumePatch, error)
    ExpireBreakpoint(id string) error // timeout/stale: completed, late Resume inactive
    Subscribe(cap int) (<-chan Event, func())
    Generation() uint64
    Epoch() uint64
    Stats() model.StoreStats
    Wipe()
    ReplaceCaps(opts Options, force bool) error
    ResetTo(opts Options) error
}
```

`Update` is **not** on the interface. Body capture uses `Insert` of the completed flow (or `Resume` patch). Do not mutate a live `*Flow` from two goroutines.

## Breakpoint contract

RULES-001 wires the proxy session to these primitives **without REST**. The HTTP-free unit test remains the contract:

- `Insert` of a paused flow **or** `Pause(id)` sets `State=paused` and emits `Event{Kind:"paused"}`.
- The **proxy session** calls `WaitPaused(ctx, id)` with a context whose deadline is `min(rule.breakpoint.timeout, store.maxWait)`. Timeout lives in that ctx — **not** a store timer that outlives `Wipe`.
- `Resume` / `Drop` wake `WaitPaused`. `Resume` on a non-paused id → `ErrBreakpointInactive`. `Drop` marks `State=dropped`.
- After `WaitPaused` the session **re-looks up** the flow. If a Resume raced the ctx timeout, honor the applied patch. If the row is still paused (timeout / `ErrStaleEpoch`), `ExpireBreakpoint` marks it `completed` with `Error=breakpoint_timeout` so a late Resume is inactive; the hop continues unmodified without a second Insert.
- **Lock order:** store mutex is never held across a proxy network read/write. Proxy session: (1) release any store lock, (2) `WaitPaused`, (3) re-lookup the flow.
- `Wipe` / `ResetTo` / stale `epoch` on `Resume`/`Drop`/`WaitPaused` → `ErrStaleEpoch`; all waiters cancel.
- `Subscribe` is the single event hook. REST SSE and MCP `subscriptions/listen` adapt it; they do not invent a second bus.

## Addressing and identity

- `id`: Crockford base32 ULID via **`github.com/oklog/ulid/v2`**. Time-sortable, unique, URL-safe.

## Caps, byte accounting, and eviction

```yaml
store:
  maxFlows: 1000
  maxBytes: 256MiB
  maxBodyBytes: 1MiB
  fullPolicy: reject        # or evict_oldest
  maxWait: 60s
  spillDirectory: ""
  spillThreshold: 256KiB
```

Caps are **stacked**:

```
resident          = Σ (len(reqBody) + len(respBody) + header budget + WS frames)
reservedInFlight  = Σ reservations at request start (each ≤ 2*maxBodyBytes + header slack)
storeOK           ⇔ (resident + candidate) ≤ maxBytes ∧ flowCount < maxFlows
inFlightOK        ⇔ reservedInFlight ≤ maxInFlightBytes
insertAllowed     ⇔ storeOK ∧ inFlightOK
```

WebSocket frames (D67, `inspectFrames`): each captured frame counts **64 bytes + `len(Payload)`** in `ResidentBytes`. All frame payloads on one flow share `store.maxBodyBytes`; the slice stops at 4096 frames. Concatenated captured payload over `spillThreshold` writes `{ULID}-ws.body` (Wipe unlinks `^[ULID]-(req|resp|ws)\.body`). List JSON omits the `frames` array (`frameCount` + `truncated` only).

| Field | Default | Notes |
|---|---|---|
| `maxFlows` | 1000 | |
| `maxBytes` | 256 MiB | stored resident only |
| `maxBodyBytes` | 1 MiB | per request body **and** per response body |
| `fullPolicy` | `reject` | or `evict_oldest` |
| `maxWait` | 60s | Wait() cap |
| `spillDirectory` | `""` | empty = RAM; tmpfs still counts |
| `spillThreshold` | 256 KiB | |

Bodies larger than `maxBodyBytes` follow the [stream vs mutate](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md#stream-vs-mutate-bodies) paths.

A single flow whose stored size exceeds `maxBytes` → `store.ErrTooLarge` (flow dropped from store; client still served if already in flight).

`fullPolicy: reject` → new flow not stored (`store.ErrFull`); proxy **still forwards** (capture is best-effort when full). Metric `labmitm_store_full_total`. This differs from LabMail (SMTP 452) because refusing to proxy when the inspector is full would break the system under test.

`evict_oldest`: delete oldest `CompletedAt` (or `StartedAt` if still open) until the new flow fits.

Spill writes bodies over `spillThreshold` under tmpfs. **tmpfs is still RAM.** `Wipe` / process exit unlinks files. Startup `Wipe`s the configured spill path. Spill is not a flow-directory across restarts.

Default worst-case RSS: `maxBytes` (256 MiB) + `maxInFlightBytes` (64 MiB) + stream slack (4 MiB) + ~64 MiB process ≈ **388 MiB**.

## Epoch and generation

- `Wipe` / `ResetTo` increment `epoch`. A session captures epoch at request start. `Insert` / `Pause` / `Resume` / `Drop` with a stale epoch is discarded (`store.ErrStaleEpoch`); the empty store stays empty after reset.
- `storeGeneration` increments on insert, delete, wipe, evict, and breakpoint state change (`paused` / `resumed` / `dropped`). Not on metrics ticks.

## `replaceStoreCaps` that shrinks below current occupancy

| `fullPolicy` after apply | Rule |
|---|---|
| `reject` | Apply **fails** `store_over_new_cap` (HTTP 400) unless the request sets `force: true`, which evicts oldest until under the new caps. |
| `evict_oldest` | Apply succeeds and immediately evicts oldest until under the new caps. |

## Related documents

- Proxy stream vs mutate: [docs/02-proxy-semantics.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md)
- Reset / wipe: [docs/06-state-and-configuration.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/06-state-and-configuration.md)
- REST wait/resume: [docs/08-rest-api.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/08-rest-api.md)

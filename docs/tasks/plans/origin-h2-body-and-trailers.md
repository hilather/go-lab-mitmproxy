# Plan: OriginConn request-body + response-trailer completeness

Status: ACCEPT (sweep 1 NO BLOCKING FINDINGS; non-blocking wording folded)
Owners: Proxy / http2x
Last reviewed: 2026-08-30
Scope: `internal/http2x.OriginConn` plus the one reconstruct helper that feeds it. Do not merge. Do not rebase/merge leftover drafts #48 / #51.

This document is an implementation contract. Origin `agent-skills` clone was unavailable (`origin auth`: Not logged in); skeptic templates still run from the task prompt.

## Verdict (planning)

Investigate-first. Implement only after review-plan + skeptic-plan-review report **NO BLOCKING FINDINGS**.

One PR from current `main` (`6a0ba36` at plan time; fetch/rebase onto latest `origin/main` before branching). Both leftovers are one OriginConn completeness gap (request DATA + response trailing HEADERS). Sequential implementation inside that PR: body first, trailers second.

## Problem (verified on current main)

`internal/http2x/origin_conn.go` on `main`:

1. **Request bodies dropped.** `requestHasBody` (lines 211–216) returns `req.ContentLength != 0`. A present `Body` with `ContentLength == 0` is treated as no body, so `RoundTrip` writes HEADERS with `END_STREAM` and never calls `writeRequestBody`. Live intercept reconstructs inner h2 streams via `reconstructH2Request` (`internal/proxy/intercept.go` 661–670) which leaves the Go zero value `ContentLength: 0` and only copies `in.Body`. Typical h2 / gRPC POSTs omit `content-length`. Origin sees an empty stream.

2. **Response trailers dropped.** `handleHeaders` (388–419) does `select { case st.hdr <- fields: default: // trailers: close body }`. The `hdr` channel is capacity 1. After `RoundTrip` drains the first block, a second HEADERS (gRPC `grpc-status`) hits `default` and is discarded. There is no `storeTrailers` / `trailerBody` / `Response.Trailer`. `drainOriginBody` (`intercept.go` 730–741) already copies `resp.Trailer` onto the flow and `roundTripInnerH2` returns those trailers to `writeResponse` — the intercept path is already wired; OriginConn never fills `Trailer`. 1xx informational HEADERS would take the `hdr` slot and become the RoundTrip status.

Drafts that already attempted this and now conflict with post-1.3/1.4/1.5 docs: [#48](https://github.com/hilather/go-lab-mitmproxy/pull/48), [#51](https://github.com/hilather/go-lab-mitmproxy/pull/51). Do **not** merge or rebase those branches. Re-apply the code/test intent onto current main.

## Non-goals

- Merging, rebasing, or closing #48 / #51.
- New intercept features (handshake, CONNECT, push-forward, inner ServeClient trailers, request-trailer forwarding toward origin).
- Changing `dropH2RequestTrailers` / h2→h1 `labmitm_h2_trailer_dropped_total` (that path stays).
- Forwarding 1xx to the inner client (skip only, so they cannot steal status/trailer).
- Push-stream trailers (`pushStream` stays first-response-headers only).
- ADR (no invariant change; D64/D65 already exist).
- `AGENTS.md` / any `DESIGN` file (neither documents origin-h2 body/trailer behavior).
- New dependencies.

## Evidence (verified)

| Claim | Evidence |
|---|---|
| `requestHasBody` treats CL==0 as no body | `origin_conn.go` 211–216: `return req.ContentLength != 0` |
| Reconstruct leaves CL 0 | `intercept.go` 661–670: `Body: in.Body`, no `ContentLength` assignment |
| Inner GET/POST always has a non-nil `Body` | `serve.go` 276–284: every stream gets `newBodyBuf`; END_STREAM closes it |
| Trailers comment only | `origin_conn.go` 396–400: `default: // trailers: close body` |
| Success RoundTrip does not `forget` the stream | `origin_conn.go` 201–207: returns `resp` while `st` stays in `o.streams` (required so later HEADERS can still attach) |
| Intercept already reads `resp.Trailer` | `intercept.go` 737–848: `drainOriginBody` → `sess.respTrailers`; `roundTripInnerH2` returns `trailers` |
| Inner encoder already emits trailing HEADERS | `serve.go` `writeResponse` 507–583: `hasTrailers` → second HEADERS + END_STREAM |
| net/http unknown-length | `Request.outgoingLength`: nil/NoBody → 0; `ContentLength != 0` → that length; else `-1`. Non-nil Body is a body. |
| Helpers for draft tests exist | `h2TLSPair` (`helper_test.go`); `startTLSOriginH2`, `hostPort` (`helper_test.go`); `interceptH2OriginSpec`, `h2ClientConnViaProxy` (`intercept_h2_test.go` 39–66); `NewNull` (`capture.go`); `appLabResolver` (`intercept_test.go`) |
| Numbered pack already documents origin-h2 multiplex | `docs/02-proxy-semantics.md` 204; `docs/12-testing-strategy.md` 17–18; `docs/known-limitations.md` 108 |
| AGENTS.md does not mention body/trailer | grep: no origin-h2 / ContentLength / grpc-status in `AGENTS.md` |
| CHANGELOG Unreleased Fixed is empty | `CHANGELOG.md` 15–17: `None.` |
| Docs have moved since the drafts | Last reviewed 2026-08-28/29; Unreleased must not replay the drafts’ already-shipped replay-FD bullets |

## Design

### 1. `requestHasBody` (http2x)

Match `net/http.Request.outgoingLength` / draft #48:

```go
func requestHasBody(req *http.Request) bool {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return false
	}
	return true
}
```

`ContentLength == 0` + non-nil Body is unknown-length, not empty. `writeRequestBody` already sends a final empty DATA+END_STREAM on immediate EOF (origin_conn.go 248–252), so GET with a closed empty `bodyBuf` stays valid HTTP/2 (HEADERS without END_STREAM, then empty DATA+END_STREAM).

Do **not** treat `ContentLength == 0` as “no body”. That is the bug.

### 2. `reconstructH2Request` ContentLength (same bug, not new intercept work)

`requestHasBody` alone is sufficient for OriginConn. Draft #48 also set reconstructed length so the request is honest for any other CL check, and shipped `TestReconstructH2RequestUnknownBodyLength`. Include that 10-line companion:

Match draft #48 exactly (`strconv` import on `intercept.go`):

```go
if cl := hdr.Get("Content-Length"); cl != "" {
    if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
        req.ContentLength = n
    } else {
        req.ContentLength = -1
    }
} else if req.Body != nil && req.Body != http.NoBody {
    req.ContentLength = -1
}
```

Do not set `-1` for `http.NoBody`. This helper is also used by h2c; those websocket paths already force `ContentLength = 0` + `NoBody`.

This is not handshake/CONNECT/push work. Do not touch `innerH2Tunnel` (it already forces `ContentLength = 0` + `NoBody`).

### 3. Response trailers + skip 1xx (http2x)

Re-apply draft #51 shape; match existing http2x style (`atomic`, `hopHeaders`, no new deps):

- `originStream` gains `gotResp atomic.Bool`, `trailers []hpack.HeaderField`, `trMu sync.Mutex`.
- `storeTrailers` / `takeTrailers` under `trMu`.
- `trailerBody` wraps the response body; `promote()` is `sync.Once` (ReadAll+Close both fire). Copies stored fields onto `resp.Trailer` at EOF **and** Close (stdlib convention). Skip empty names, `:` pseudos, `hopHeaders`, and `trailer`.
- `RoundTrip` success path: `resp.Trailer = make(http.Header)` and wrap `resp.Body` with `trailerBody`. **Do not `forget(id)` on success** — later HEADERS must still see `st`.
- `handleHeaders` for `st != nil`:
  - If `statusOf(fields)` is `1 <= status < 200`: if `StreamEnded()`, `failStream` with an informational-ended-stream error; then **`return`** (do not `gotResp.Swap` / `st.hdr` / fall through to the existing body-close).
  - Else `gotResp.Swap(true)`: first non-1xx → `st.hdr`; if the channel is already full, `storeTrailers` (do not drop). Subsequent blocks → `storeTrailers`.
  - Existing `StreamEnded()` → close body + `closed.Store(true)` stays (non-1xx path only).

Push path unchanged.

### 4. Docs (only files that already describe origin-h2)

Patch current main text; do not replay draft hunks that rewind Last reviewed / ADR lists / already-shipped changelog rows.

| File | Change |
|---|---|
| `internal/http2x/doc.go` | One clause: request DATA when Body is non-nil (including CL 0); trailing HEADERS on `Response.Trailer`; 1xx skipped |
| `docs/02-proxy-semantics.md` | HTTP/2 inner bullet: request DATA even when content-length omitted; origin-h2 response trailers forwarded (gRPC `grpc-status`); 1xx skipped. Last reviewed: 2026-08-30 |
| `docs/12-testing-strategy.md` | HTTP/2 codec + transcode rows: origin-h2 POST DATA (no CL); origin-h2 trailers + skip 1xx. Last reviewed: 2026-08-30 |
| `docs/known-limitations.md` | **Append** to the current line-108 sentence (keep the D44 request-trailer residual). Last reviewed: 2026-08-30 |
| `CHANGELOG.md` Unreleased **Fixed** | Two bullets (or one combined) for body + trailers. Replace `None.` Do not copy the drafts’ replay-FD lines |

Do **not** edit `AGENTS.md`.

### 5. Tests (must fail on current main)

Port draft tests; they are written against helpers that still exist.

**http2x (`origin_conn_test.go`):**

- `TestOriginConnPOSTBodyZeroContentLength` — POST Body + `ContentLength: 0`; origin must see DATA.
- `TestRequestHasBodyZeroContentLength` — table: CL 0 + Body → true; `NoBody` / nil Body → false.
- `TestOriginConnRoundTripResponseTrailers` — `http2.Server` gRPC-style `Trailer` + `Grpc-Status` / `Grpc-Message`.
- `TestOriginConnSkips1xxThenForwardsTrailers` — framer helper `writeInformationalThenTrailers`: 103, then 200 + DATA, then trailer HEADERS. Status must be 200; trailer `x-checksum=abc`.

**proxy (`intercept_h2_test.go`):**

- `TestInterceptHTTP2OriginH2POSTBody` — `interceptH2OriginSpec`, `ContentLength: -1` pipe body; origin must see payload and negotiate h2.
- `TestReconstructH2RequestUnknownBodyLength` — omitted CL → `-1`; `content-length: 5` → 5.
- `TestInterceptHTTP2OriginH2ForwardsResponseTrailers` — origin sets gRPC trailers; inner client `resp.Trailer` and captured `flow.Response.Trailers` both see them.

These fail on current main: POST CL 0 never writes DATA; second HEADERS never reach `Response.Trailer`.

### 6. PR / git

- Branch: `cursor/origin-h2-body-trailers-bd9c` off fetched `origin/main`.
- One draft PR. Do not merge. Do not update #48/#51.
- Commit after implementation, push, open PR, then run tests (cloud-agent loop).

## Review

- review-plan: claims checked against `origin_conn.go`, `intercept.go`, `serve.go`, helpers. No blocking gaps.
- skeptic-plan-review sweep 1: **NO BLOCKING FINDINGS** (7 non-blocking wording/risk notes folded above).

## Implementation order

1. Fetch `origin/main`; branch `cursor/origin-h2-body-trailers-bd9c`.
2. Add draft tests first; confirm they fail on current main.
3. Body: `requestHasBody` + reconstruct CL.
4. Trailers: `originStream` / `trailerBody` / `handleHeaders` (1xx `return`).
5. Docs + CHANGELOG on current text (append known-limitations; do not rewind ADR lists).
6. `gofmt`; `go test ./internal/http2x/ ./internal/proxy/` (and race on the new tests); `make format` / `make lint` / `make test-docs` / `make test-changelog`.
7. Commit / push / PR. Then review-pr + skeptic-code-review.

## Risks (accepted)

- GET with a non-nil closed `bodyBuf` now sends an empty DATA frame. Valid HTTP/2; same as draft #48.
- 1xx is dropped, not forwarded. Matches draft #51 and the stated bug (1xx must not steal the status/trailer slot).
- `trailerBody.promote` after `forget` is not a concern: success RoundTrip does not forget; `failStream`/`failAll` still close the body with error (no trailer contract on RST).

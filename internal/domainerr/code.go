package domainerr

// Code is a stable, transport-independent domain error code.
type Code string

const (
	CodeValidationFailed    Code = "validation_failed"
	CodeUnauthenticated     Code = "unauthenticated"
	CodeForbidden           Code = "forbidden"
	CodeTargetDenied        Code = "target_denied"
	CodeNotFound            Code = "not_found"
	CodeMethodNotAllowed    Code = "method_not_allowed"
	CodeRevisionConflict    Code = "revision_conflict"
	CodeIdempotencyConflict Code = "idempotency_conflict"
	CodeStoreFull           Code = "store_full"
	CodeStoreOverNewCap     Code = "store_over_new_cap"
	CodeCursorStale         Code = "cursor_stale"
	CodeBreakpointInactive  Code = "breakpoint_inactive"
	CodeRateLimited         Code = "rate_limited"
	CodeTimeout             Code = "timeout"
	CodeInternalError       Code = "internal_error"
)

// catalog is the closed first-GA code list. Retryable is advisory per class.
var catalog = []struct {
	Code      Code
	Retryable bool
}{
	{CodeValidationFailed, false},
	{CodeUnauthenticated, false},
	{CodeForbidden, false},
	{CodeTargetDenied, false},
	{CodeNotFound, false},
	{CodeMethodNotAllowed, false},
	{CodeRevisionConflict, true},
	{CodeIdempotencyConflict, false},
	{CodeStoreFull, true},
	{CodeStoreOverNewCap, false},
	{CodeCursorStale, false},
	{CodeBreakpointInactive, false},
	{CodeRateLimited, true},
	{CodeTimeout, true},
	{CodeInternalError, true},
}

// Codes returns the stable catalog in documented order.
func Codes() []Code {
	out := make([]Code, len(catalog))
	for i, e := range catalog {
		out[i] = e.Code
	}
	return out
}

// Retryable reports the catalog default for code. Unknown codes are not retryable.
func Retryable(code Code) bool {
	for _, e := range catalog {
		if e.Code == code {
			return e.Retryable
		}
	}
	return false
}

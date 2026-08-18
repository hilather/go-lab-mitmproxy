package store

import "errors"

var (
	// ErrFull is returned when insert is rejected (fullPolicy reject).
	// The proxy still forwards; capture is best-effort.
	ErrFull = errors.New("store full")
	// ErrStaleEpoch is returned when Wipe/ResetTo raced an in-flight session
	// or a breakpoint waiter.
	ErrStaleEpoch = errors.New("stale store epoch")
	// ErrTooLarge is a single flow whose resident size exceeds maxBytes.
	ErrTooLarge = errors.New("flow exceeds store maxBytes")
	// ErrNotFound is a missing flow id.
	ErrNotFound = errors.New("flow not found")
	// ErrSpill is an unreadable or unwritable spill file.
	ErrSpill = errors.New("store spill")
	// ErrOverNewCap is replaceStoreCaps when occupancy exceeds the new
	// reject caps and force is false.
	ErrOverNewCap = errors.New("store over new cap")
	// ErrBreakpointInactive is Resume/Drop/WaitPaused on a non-paused id.
	ErrBreakpointInactive = errors.New("breakpoint inactive")
	// ErrDropped is WaitPaused after Drop.
	ErrDropped = errors.New("breakpoint dropped")
	// ErrBreakpointTimeout is ExpireBreakpoint / WaitPaused after a
	// session-ctx timeout (not a store timer).
	ErrBreakpointTimeout = errors.New("breakpoint timeout")
)

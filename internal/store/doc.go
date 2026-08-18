// Package store is the ephemeral flow inbox used by the proxy.
//
// Sink is the insert/epoch API. Memory is the bounded ULID inbox. Null
// acknowledges flows and retains nothing. ReplaceCaps implements
// replaceStoreCaps shrink rules; Wipe and ResetTo are the only epoch bumps.
// Pause/Resume/Drop/WaitPaused are breakpoint primitives for RULES-001
// (no REST required).
package store

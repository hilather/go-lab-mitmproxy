// Package snapshot holds the compiled immutable config snapshot and its atomic store.
//
// Proxy sessions load the active snapshot once per request / CONNECT. The
// flow store is not part of the snapshot. Callers must not mutate Canonical,
// Rules, or CA after Compile.
package snapshot

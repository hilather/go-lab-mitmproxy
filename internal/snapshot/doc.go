// Package snapshot holds the compiled immutable config snapshot and its atomic store.
//
// Proxy sessions load the active snapshot once per request / CONNECT. The
// flow store is not part of the snapshot. Callers must not mutate Canonical,
// Rules, CA, or SOCKSUsers after Compile. SOCKSUsers is a side table (not
// Canonical) loaded only on Start/Reset.
package snapshot

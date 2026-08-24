// Package compiler compiles a LabMITM document into a canonical snapshot.
//
// Compile calls config.Normalize + config.Validate, hashes the canonical
// spec, builds the rules engine, generates or loads the lab CA, and loads
// SOCKS user-pass digests on Start/Reset (copy Previous.SOCKSUsers on live
// Compile). This is the only compiler (rules PR 6 has none). The returned
// Snapshot is immutable; callers must not mutate Canonical, Rules, CA, or
// SOCKSUsers. internal/snapshot.Store holds the live pointer that the proxy
// re-reads.
package compiler

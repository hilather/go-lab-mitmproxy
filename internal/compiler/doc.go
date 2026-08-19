// Package compiler compiles a LabMITM document into a canonical snapshot.
//
// Compile calls config.Normalize + config.Validate, hashes the canonical
// spec, builds the rules engine, and generates or loads the lab CA. This
// is the only compiler (rules PR 6 has none). The returned Snapshot is
// immutable; callers must not mutate Canonical, Rules, or CA.
// internal/snapshot.Store holds the live pointer that the proxy re-reads.
package compiler

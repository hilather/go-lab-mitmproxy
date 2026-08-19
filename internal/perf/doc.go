// Package perf is the GA-001 soak harness: accept N flows, Wait, Wipe.
//
// Default N is CI-safe (8). Operators raise it with -soak-n or LABMITM_SOAK_N.
// Local lab target is ~100 flows/s for 30s (N≈3000). That is not a QPS gate.
package perf

// Package app implements shared commands, queries, plans, and reset.
//
// REST and MCP adapters must call this package rather than embedding domain
// logic. Mutations copy canonical state, apply operations, then
// normalize/validate/compile a full candidate before an atomic Store.Swap.
// The live snapshot is never edited in place. The service never writes the
// bootstrap file. Proxy insert stays on the data plane.
package app

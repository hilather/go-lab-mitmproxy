// Package capabilities is the shared capability registry and parity metadata.
//
// REST and MCP adapters register from this package. They must not invent
// paths, tool names, or resource URIs: renaming a row is a compatibility
// change and requires updating the catalog, the generated manifest, and
// docs/07-control-plane-and-parity.md together. Health live/ready, session,
// and metrics are REST-only.
//
// Error helpers map domainerr values to RFC 9457 problem+json status hints
// and JSON-RPC envelopes. They do not start an HTTP or MCP server.
package capabilities

// Package rest is the REST transport adapter for the shared capability registry.
//
// Routes are registered from internal/capabilities (catalog spellings only).
// Handlers call app.Service and contain no store or proxy mutation logic.
// Errors are capabilities.ProblemFrom → application/problem+json.
// Session cookie/CSRF routes are registered from the capability catalog.
// Config.UI (wired by cmd/labmitm from
// internal/web) serves the stub SPA after native routing misses when
// spec.ui.enabled is true. Config.Mounts (wired by cmd) serves POST /mcp
// from internal/control/mcp without this package importing MCP.
//
//go:generate go run ../../../scripts/generate
package rest

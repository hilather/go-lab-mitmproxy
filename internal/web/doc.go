// Package web embeds the production React flow-inspector (or a compile-time
// stub) and serves it with SPA fallback. Production files are copied into
// dist/ by `make web-build`; go:embed cannot reach web/ because of web/go.mod.
package web

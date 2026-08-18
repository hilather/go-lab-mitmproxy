// Package rules is the deterministic first-match rewrite / breakpoint engine.
//
// It evaluates a constructed RulesSpec (tests and the proxy). YAML compile
// into a snapshot is STA-001 / internal/compiler — not this package.
// Master switch spec.rules.enabled is default-off. No weights, no hash, no
// random (D12). Production files import model only.
package rules

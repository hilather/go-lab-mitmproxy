// Package proxy is the HTTP/1.1 forward-proxy data plane.
//
// It accepts absolute-form http:// requests and CONNECT tunnels. Accept
// never peeks (D42): a per-conn goroutine peeks one byte under
// HeaderTimeout and closes SOCKS (0x04/0x05) when accept flags are off.
// HTTP/2 preface is a hard close in the Handler. TLS intercept
// (tls.intercept:true on listed ports) mints a lab
// leaf and runs an inner HTTP/1.1 session; handshake failure closes both
// sides and does not fall back to a blind tunnel (D20). Production Dial
// lives only here (D16). Request/response rules (internal/rules) run after
// parse and after upstream headers; capture-only tees, mutating actions
// buffer to maxBodyBytes (D21).
//
// When Options.Snapshots is set, each request / CONNECT loads the atomic
// snapshot once and pins spec, rules engine, and CA for the session.
package proxy

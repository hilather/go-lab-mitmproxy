// Package proxy is the HTTP/1.1 forward-proxy data plane.
//
// It accepts absolute-form http:// requests and CONNECT tunnels. SOCKS is
// rejected on Accept (peekListener). HTTP/2 preface is a hard close in the
// Handler. TLS intercept is a stub until TLS-001: intercept:true still
// raw-tunnels. Production Dial lives only here (D16).
package proxy

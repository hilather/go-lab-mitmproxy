// Package proxy is the HTTP/1.1 forward-proxy data plane.
//
// It accepts absolute-form http:// requests and CONNECT tunnels. SOCKS is
// rejected on Accept (peekListener). HTTP/2 preface is a hard close in the
// Handler. TLS intercept (tls.intercept:true on listed ports) mints a lab
// leaf and runs an inner HTTP/1.1 session; handshake failure closes both
// sides and does not fall back to a blind tunnel (D20). Production Dial
// lives only here (D16).
package proxy

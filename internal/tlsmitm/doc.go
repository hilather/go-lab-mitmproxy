// Package tlsmitm is the in-process lab CA and dual TLS handshake.
//
// It generates or loads a laboratory CA, mints per-host leaves, and
// handshakes tls.Server / tls.Client on already-dialed connections.
// Production files in this package must not Dial (D16).
//
// The CA handle is compiled into the immutable snapshot (internal/compiler).
// The proxy pins that handle at CONNECT accept and passes it into
// HandshakeServer / HandshakeClient so a later replaceTLS cannot rotate
// an in-flight session onto a new CA. Handshake NextProtos come from the
// session snapshot (D46), not from Authority compile.
package tlsmitm

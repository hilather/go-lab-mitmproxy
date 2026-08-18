// Package tlsmitm is the in-process lab CA and dual TLS handshake.
//
// It generates or loads a laboratory CA, mints per-host leaves, and
// handshakes tls.Server / tls.Client on already-dialed connections.
// Production files in this package must not Dial (D16).
package tlsmitm

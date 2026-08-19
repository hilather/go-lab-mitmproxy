// Package auth is the shared lab-static-bearer verifier for REST (and later MCP).
//
// Bearer is the only 1.0 authenticator. There is no HTTP Basic. Tokens are
// compared as SHA-256 digests; secret files are the only durable secret.
// Session cookie/CSRF is SEC-001. This package must not allow-all: a bearer
// mode with no usable token cannot bind management.
package auth

// Package domainerr defines stable domain error codes and problem mappings.
//
// Public errors contain a code, message, retryable flag, optional field
// violations, current revision, and remediation. They never include secrets
// or stack traces.
package domainerr

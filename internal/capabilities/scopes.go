package capabilities

// Frozen first-GA scopes. Role binding is in internal/auth; adapters must not
// invent synonyms.
const (
	ScopeMITMRead      = "mitm.read"
	ScopeMITMWrite     = "mitm.write"
	ScopeMITMAdmin     = "mitm.admin"
	ScopeMITMAuditRead = "mitm.audit.read"
)

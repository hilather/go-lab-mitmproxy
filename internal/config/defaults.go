package config

import "time"

// Materialized v1alpha1 defaults. Zero values on the Go types are not these
// values until Decode/Normalize run.
const (
	DefaultProxyAddress         = "127.0.0.1:8888"
	DefaultMgmtAddress          = "127.0.0.1:8088"
	DefaultOrigDestAddress      = "127.0.0.1:8890"
	DefaultRESTPath             = "/v1"
	DefaultMCPPath              = "/mcp"
	DefaultCompatPathPrefix     = "/compat"
	DefaultMaxConcurrentStreams = 100
	DefaultProxyHostname        = "labmitm.lab"
	DefaultMaxSessions          = 256
	DefaultMaxSessionsPerIP     = 32
	DefaultMaxInFlight          = 64
	DefaultMaxInFlightBytes     = int64(64 << 20)
	DefaultSessionTimeout       = 10 * time.Minute
	DefaultIdleTimeout          = 120 * time.Second
	DefaultHeaderTimeout        = 10 * time.Second
	DefaultDialTimeout          = 10 * time.Second
	DefaultUpstreamTimeout      = 60 * time.Second
	DefaultMaxFlows             = 1000
	DefaultStoreMaxBytes        = int64(256 << 20)
	DefaultMaxBodyBytes         = int64(1 << 20)
	DefaultStoreMaxWait         = 60 * time.Second
	DefaultSpillThreshold       = int64(256 << 10)
	DefaultBodyLimit            = int64(1 << 20)
	DefaultRequestsPerSecond    = 32
	DefaultBurst                = 64
	DefaultMaxConcurrent        = 256
	DefaultAuditRing            = 128
	DefaultMetricsListen        = "127.0.0.1:9090"
	DefaultSessionMax           = 64
	DefaultStreamSlack          = int64(64 << 10) // per in-flight copy buffer
	MaxDocumentBytes            = 1 << 20
	MaxRuleDelay                = 30 * time.Second
	MaxBreakpointTimeout        = 60 * time.Second
	MaxRuleBodyReplace          = int64(64 << 10)

	minStoreMaxBytes = int64(1 << 20)
	minMaxBodyBytes  = int64(1 << 10)
	minTokenSecret   = 32
	minRFC1929Secret = 1
	maxRFC1929Secret = 255
	defaultTLSPort   = 443

	violationUnknownField       = "unknown_field"
	violationRequired           = "required"
	violationInvalidValue       = "invalid_value"
	violationReservedName       = "reserved_name"
	violationDuplicateKey       = "duplicate_key"
	violationTooLarge           = "document_too_large"
	violationUnsupportedVersion = "unsupported_version"
	violationUnresolved         = "unresolved_reference"
	violationDuplicateID        = "duplicate_id"
	violationEmptyID            = "empty_id"
)

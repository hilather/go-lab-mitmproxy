package capabilities

import (
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
)

// ProblemContentType is the RFC 9457 media type adapters must emit.
const ProblemContentType = "application/problem+json"

// ProblemTypePrefix is the URN namespace for domain problem types.
const ProblemTypePrefix = "urn:labmitm:error:"

// JSON-RPC 2.0 reserved codes plus the first-GA application range.
const (
	JSONRPCParseError     = -32700
	JSONRPCInvalidRequest = -32600
	JSONRPCMethodNotFound = -32601
	JSONRPCInvalidParams  = -32602
	JSONRPCInternalError  = -32603

	JSONRPCApplication     = -32000
	JSONRPCUnauthenticated = -32001
	JSONRPCForbidden       = -32003
	JSONRPCNotFound        = -32004
	JSONRPCRateLimited     = -32005
	JSONRPCConflict        = -32009
	JSONRPCTimeout         = -32010
)

// Problem is an RFC 9457 problem+json document with domainerr extensions.
// Adapters fill Instance (request URN) and serialize; no HTTP server lives here.
type Problem struct {
	Type            string                     `json:"type"`
	Title           string                     `json:"title"`
	Status          int                        `json:"status"`
	Detail          string                     `json:"detail,omitempty"`
	Instance        string                     `json:"instance,omitempty"`
	Code            domainerr.Code             `json:"code"`
	Retryable       bool                       `json:"retryable"`
	FieldViolations []domainerr.FieldViolation `json:"fieldViolations,omitempty"`
	CurrentRevision string                     `json:"currentRevision,omitempty"`
	Remediation     string                     `json:"remediation,omitempty"`
}

// JSONRPCError is a JSON-RPC 2.0 error object. Data is the same domain
// error REST exposes in problem extensions.
type JSONRPCError struct {
	Code    int              `json:"code"`
	Message string           `json:"message"`
	Data    *domainerr.Error `json:"data"`
}

type mapping struct {
	Status int
	RPC    int
	Title  string
}

// status and JSON-RPC codes differ by transport; domain Code stays the same.
var errorMap = map[domainerr.Code]mapping{
	domainerr.CodeValidationFailed:    {400, JSONRPCInvalidParams, "Validation failed"},
	domainerr.CodeUnauthenticated:     {401, JSONRPCUnauthenticated, "Unauthenticated"},
	domainerr.CodeForbidden:           {403, JSONRPCForbidden, "Forbidden"},
	domainerr.CodeTargetDenied:        {403, JSONRPCForbidden, "Target denied"},
	domainerr.CodeNotFound:            {404, JSONRPCNotFound, "Not Found"},
	domainerr.CodeMethodNotAllowed:    {405, JSONRPCMethodNotFound, "Method not allowed"},
	domainerr.CodeRevisionConflict:    {409, JSONRPCConflict, "State revision conflict"},
	domainerr.CodeIdempotencyConflict: {409, JSONRPCConflict, "Idempotency key conflict"},
	domainerr.CodeStoreFull:           {409, JSONRPCConflict, "Store full"},
	domainerr.CodeStoreOverNewCap:     {400, JSONRPCInvalidParams, "Store over new cap"},
	domainerr.CodeCursorStale:         {400, JSONRPCInvalidParams, "Cursor stale"},
	domainerr.CodeBreakpointInactive:  {409, JSONRPCConflict, "Breakpoint inactive"},
	domainerr.CodeRateLimited:         {429, JSONRPCRateLimited, "Rate limited"},
	domainerr.CodeTimeout:             {504, JSONRPCTimeout, "Timeout"},
	domainerr.CodeInternalError:       {500, JSONRPCInternalError, "Internal error"},
}

func lookupMapping(code domainerr.Code) mapping {
	if m, ok := errorMap[code]; ok {
		return m
	}
	return mapping{Status: 500, RPC: JSONRPCInternalError, Title: "Internal error"}
}

// ProblemTypeURN is the RFC 9457 type for code (underscores become hyphens).
func ProblemTypeURN(code domainerr.Code) string {
	return ProblemTypePrefix + strings.ReplaceAll(string(code), "_", "-")
}

// HTTPStatus is the REST status hint for code. Unknown codes are 500.
func HTTPStatus(code domainerr.Code) int {
	return lookupMapping(code).Status
}

// JSONRPCCode is the JSON-RPC error code for a domain code.
func JSONRPCCode(code domainerr.Code) int {
	return lookupMapping(code).RPC
}

// TitleFor is the problem title for code.
func TitleFor(code domainerr.Code) string {
	return lookupMapping(code).Title
}

func domainOf(err error) *domainerr.Error {
	if de, ok := domainerr.As(err); ok && de != nil {
		return de
	}
	return domainerr.Internal("internal error")
}

// ProblemFrom maps err to a problem+json document. instance is the optional
// request URN (docs/08 example: urn:labmitm:request:...).
func ProblemFrom(err error, instance string) Problem {
	de := domainOf(err)
	m := lookupMapping(de.Code)
	p := Problem{
		Type:            ProblemTypeURN(de.Code),
		Title:           m.Title,
		Status:          m.Status,
		Detail:          de.Message,
		Instance:        instance,
		Code:            de.Code,
		Retryable:       de.Retryable,
		CurrentRevision: de.CurrentRevision,
		Remediation:     de.Remediation,
	}
	if len(de.FieldViolations) > 0 {
		p.FieldViolations = append([]domainerr.FieldViolation(nil), de.FieldViolations...)
	}
	return p
}

// JSONRPCFrom maps err to a JSON-RPC error. Data is a copy of the domain
// error so adapters do not share the caller's struct.
func JSONRPCFrom(err error) JSONRPCError {
	de := domainOf(err)
	cp := *de
	if de.FieldViolations != nil {
		cp.FieldViolations = append([]domainerr.FieldViolation(nil), de.FieldViolations...)
	}
	msg := de.Message
	if msg == "" {
		msg = lookupMapping(de.Code).Title
	}
	return JSONRPCError{
		Code:    lookupMapping(de.Code).RPC,
		Message: msg,
		Data:    &cp,
	}
}

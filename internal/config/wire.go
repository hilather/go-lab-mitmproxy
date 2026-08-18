package config

import "github.com/hilather/go-lab-mitmproxy/internal/domainerr"

// CoerceWireTree converts duration and byte-size strings in a decoded JSON
// tree (UseNumber) so encoding/json can populate model types. Used by REST
// plan/apply bodies that carry the same spellings as YAML.
func CoerceWireTree(v any) []domainerr.FieldViolation {
	vs := convertDurations(v, "")
	return append(vs, convertByteSizes(v, "")...)
}

// FormatWireTree rewrites duration and byte-size numbers to canonical strings
// for REST JSON responses.
func FormatWireTree(v any) {
	convertDurationNumbersToStrings(v)
	convertByteSizeNumbersToStrings(v)
}

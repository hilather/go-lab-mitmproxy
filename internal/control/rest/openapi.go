package rest

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// OpenAPIRelPath is the generated OpenAPI document, relative to the module root.
const OpenAPIRelPath = "api/openapi/v1.json"

// OpenAPIVersion is the OpenAPI specification version of the generated file.
const OpenAPIVersion = "3.1.0"

// RenderOpenAPI builds OpenAPI 3.1 JSON from the capability registry.
func RenderOpenAPI() ([]byte, error) {
	doc := map[string]any{
		"openapi": OpenAPIVersion,
		"info": map[string]any{
			"title":          "LabMITM Management API",
			"version":        capabilities.VersionTag,
			"description":    "REST adapter for the shared LabMITM capability registry. Generated from internal/capabilities. Do not edit by hand.",
			"x-generated-by": "internal/control/rest.RenderOpenAPI; DO NOT EDIT.",
		},
		"servers": []any{
			map[string]any{"url": "/", "description": "Management listener (default address " + DefaultAddr + ")"},
		},
		"tags":       openAPITags(),
		"paths":      openAPIPaths(),
		"components": openAPIComponents(),
		"security":   []any{map[string]any{"bearerAuth": []any{}}},
	}
	return marshalSorted(doc)
}

func openAPITags() []any {
	seen := map[string]bool{}
	var tags []any
	for _, c := range capabilities.All() {
		name := tagFor(c)
		if seen[name] {
			continue
		}
		seen[name] = true
		tags = append(tags, map[string]any{"name": name, "description": c.Description})
	}
	return tags
}

func tagFor(c capabilities.Capability) string {
	s := string(c.ID)
	if i := strings.IndexByte(s, '.'); i > 0 {
		return s[:i]
	}
	return s
}

func openAPIPaths() map[string]any {
	paths := map[string]any{}
	for _, c := range capabilities.All() {
		for _, b := range c.REST {
			item, _ := paths[b.Path].(map[string]any)
			if item == nil {
				item = map[string]any{}
			}
			item[strings.ToLower(b.Method)] = openAPIOperation(c, b)
			paths[b.Path] = item
		}
	}
	return paths
}

func openAPIOperation(c capabilities.Capability, b capabilities.RESTBinding) map[string]any {
	op := map[string]any{
		"operationId": operationID(b),
		"tags":        []any{tagFor(c)},
		"summary":     c.Title,
		"description": c.Description,
		"parameters":  pathParameters(b.Path),
	}
	if c.RESTOnly && (c.ID == capabilities.HealthLive || c.ID == capabilities.HealthReady) {
		op["security"] = []any{}
	}
	if len(c.RequiredScopes) > 0 {
		op["x-required-scopes"] = append([]string(nil), c.RequiredScopes...)
	}
	op["x-capability-id"] = string(c.ID)
	op["x-mutating"] = c.Mutating
	op["x-idempotent"] = c.Idempotent
	if c.InputSchema != nil && strings.EqualFold(b.Method, "POST") {
		op["requestBody"] = map[string]any{
			"required": !optionalBody(c.ID),
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": schemaRefOrObject(c.InputSchema.Name),
				},
			},
		}
	}
	if strings.HasPrefix(b.Path, "/v1/state:export") {
		params, _ := op["parameters"].([]any)
		params = append(params, map[string]any{
			"name":        "format",
			"in":          "query",
			"required":    false,
			"description": "Export encoding. Omitted or yaml returns canonical YAML. json returns a metadata wrapper.",
			"schema":      map[string]any{"type": "string", "enum": []any{"yaml", "json"}, "default": "yaml"},
		})
		op["parameters"] = params
	}
	if b.Path == "/v1/flows" && strings.EqualFold(b.Method, "GET") {
		params, _ := op["parameters"].([]any)
		params = append(params,
			map[string]any{"name": "host", "in": "query", "schema": map[string]any{"type": "string"}},
			map[string]any{"name": "method", "in": "query", "schema": map[string]any{"type": "string"}},
			map[string]any{"name": "status", "in": "query", "schema": map[string]any{"type": "integer"}},
			map[string]any{"name": "scheme", "in": "query", "schema": map[string]any{"type": "string"}},
			map[string]any{"name": "intercepted", "in": "query", "schema": map[string]any{"type": "boolean"}},
			map[string]any{"name": "ruleId", "in": "query", "schema": map[string]any{"type": "string"}},
			map[string]any{"name": "cursor", "in": "query", "schema": map[string]any{"type": "string"}},
			map[string]any{"name": "limit", "in": "query", "schema": map[string]any{"type": "integer", "minimum": 0, "maximum": 200, "default": 50}},
		)
		op["parameters"] = params
	}
	if b.Path == "/v1/audit" {
		params, _ := op["parameters"].([]any)
		params = append(params,
			map[string]any{"name": "limit", "in": "query", "schema": map[string]any{"type": "integer", "minimum": 0}},
		)
		op["parameters"] = params
	}
	op["responses"] = openAPIResponses(c, b)
	return op
}

func optionalBody(id capabilities.ID) bool {
	switch id {
	case capabilities.StateReset, capabilities.FlowsResume, capabilities.FlowsDrop, capabilities.FlowsReplay:
		return true
	default:
		return false
	}
}

func operationID(b capabilities.RESTBinding) string {
	p := strings.TrimPrefix(b.Path, "/")
	p = strings.ReplaceAll(p, "/", "_")
	p = strings.ReplaceAll(p, "{", "")
	p = strings.ReplaceAll(p, "}", "")
	p = strings.ReplaceAll(p, ":", "_")
	p = strings.ReplaceAll(p, "-", "_")
	return strings.ToLower(b.Method) + "_" + p
}

func pathParameters(path string) []any {
	var out []any
	for _, seg := range compilePath(path) {
		if seg.wild == "" {
			continue
		}
		out = append(out, map[string]any{
			"name":     seg.wild,
			"in":       "path",
			"required": true,
			"schema":   map[string]any{"type": "string"},
		})
	}
	if out == nil {
		return []any{}
	}
	return out
}

func openAPIResponses(c capabilities.Capability, b capabilities.RESTBinding) map[string]any {
	success := "200"
	successSchema := map[string]any{"type": "object"}
	contentType := "application/json"
	if c.OutputSchema != nil {
		successSchema = schemaRefOrObject(c.OutputSchema.Name)
	}
	switch c.ID {
	case capabilities.HealthLive, capabilities.HealthReady:
		successSchema = map[string]any{"$ref": "#/components/schemas/Health"}
	case capabilities.SchemaGet:
		contentType = "application/schema+json"
	case capabilities.CAGet:
		contentType = "application/x-pem-file"
		successSchema = map[string]any{"type": "string", "format": "binary"}
	case capabilities.FlowsRequest, capabilities.FlowsResponse:
		contentType = "application/octet-stream"
		successSchema = map[string]any{"type": "string", "format": "binary"}
	case capabilities.EventsStream:
		contentType = "text/event-stream"
		successSchema = map[string]any{"type": "string"}
	case capabilities.FlowsDelete, capabilities.FlowsResume, capabilities.FlowsDrop:
		success = "204"
	case capabilities.MetricsGet:
		contentType = "text/plain"
	case capabilities.StateExport:
		return map[string]any{
			"200": map[string]any{
				"description": "Canonical export.",
				"content": map[string]any{
					"application/yaml": map[string]any{"schema": map[string]any{"type": "string"}},
					"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/Export"}},
				},
			},
			"default": problemResponse(),
		}
	}
	resp := map[string]any{"description": c.Title}
	if success != "204" {
		resp["content"] = map[string]any{
			contentType: map[string]any{"schema": successSchema},
		}
	}
	_ = b
	return map[string]any{
		success:   resp,
		"default": problemResponse(),
	}
}

func problemResponse() map[string]any {
	return map[string]any{
		"description": "application/problem+json domain error",
		"content": map[string]any{
			capabilities.ProblemContentType: map[string]any{
				"schema": map[string]any{"$ref": "#/components/schemas/Problem"},
			},
		},
	}
}

func schemaRefOrObject(name string) map[string]any {
	if name == "" {
		return map[string]any{"type": "object"}
	}
	return map[string]any{"$ref": "#/components/schemas/" + sanitizeSchemaName(name)}
}

func sanitizeSchemaName(name string) string {
	return strings.ReplaceAll(name, ".", "")
}

func openAPIComponents() map[string]any {
	schemas := map[string]any{
		"Problem": map[string]any{
			"type":     "object",
			"required": []any{"type", "title", "status", "code"},
			"properties": map[string]any{
				"type":            map[string]any{"type": "string"},
				"title":           map[string]any{"type": "string"},
				"status":          map[string]any{"type": "integer"},
				"detail":          map[string]any{"type": "string"},
				"instance":        map[string]any{"type": "string"},
				"code":            map[string]any{"type": "string"},
				"retryable":       map[string]any{"type": "boolean"},
				"fieldViolations": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/FieldViolation"}},
				"currentRevision": map[string]any{"type": "string"},
				"remediation":     map[string]any{"type": "string"},
			},
		},
		"FieldViolation": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path":    map[string]any{"type": "string"},
				"code":    map[string]any{"type": "string"},
				"message": map[string]any{"type": "string"},
			},
		},
		"Health": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"status": map[string]any{"type": "string"},
			},
		},
		"State": specSchema(),
	}
	for _, c := range capabilities.All() {
		for _, ref := range []*capabilities.SchemaRef{c.InputSchema, c.OutputSchema} {
			if ref == nil || ref.Name == "" {
				continue
			}
			key := sanitizeSchemaName(ref.Name)
			if _, ok := schemas[key]; ok {
				continue
			}
			schemas[key] = map[string]any{
				"type":        "object",
				"description": "Application type " + ref.Name + ".",
			}
		}
	}
	return map[string]any{
		"securitySchemes": map[string]any{
			"bearerAuth": map[string]any{
				"type":         "http",
				"scheme":       "bearer",
				"bearerFormat": "token",
				"description":  "Lab static bearer. There is no HTTP Basic.",
			},
		},
		"schemas": schemas,
	}
}

func specSchema() map[string]any {
	return map[string]any{
		"type":        "object",
		"description": "labmitm.dev/v1alpha1 LabMITM document.",
		"required":    []any{"apiVersion", "kind", "spec"},
		"properties": map[string]any{
			"apiVersion": map[string]any{"type": "string", "const": model.APIVersionV1Alpha1},
			"kind":       map[string]any{"type": "string", "const": model.KindLabMITM},
			"metadata": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":   map[string]any{"type": "string"},
					"labels": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
				},
			},
			"spec": map[string]any{"type": "object"},
		},
	}
}

func marshalSorted(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeSorted(&buf, tree, 0); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

func writeSorted(buf *bytes.Buffer, v any, indent int) error {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteByte('\n')
			writeIndent(buf, indent+1)
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteString(": ")
			if err := writeSorted(buf, x[k], indent+1); err != nil {
				return err
			}
		}
		if len(keys) > 0 {
			buf.WriteByte('\n')
			writeIndent(buf, indent)
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, el := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteByte('\n')
			writeIndent(buf, indent+1)
			if err := writeSorted(buf, el, indent+1); err != nil {
				return err
			}
		}
		if len(x) > 0 {
			buf.WriteByte('\n')
			writeIndent(buf, indent)
		}
		buf.WriteByte(']')
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}

func writeIndent(buf *bytes.Buffer, n int) {
	for i := 0; i < n; i++ {
		buf.WriteString("  ")
	}
}

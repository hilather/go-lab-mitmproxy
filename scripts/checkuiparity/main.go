// Command checkuiparity checks the reviewed browser coverage of the public API.
// Behavioral evidence is executed separately by the mandatory web-test reporter.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/hilather/go-lab-mitmproxy/internal/capabilities"
)

type evidence struct {
	File string `json:"file"`
	Test string `json:"test"`
}

type coverage struct {
	Route    string     `json:"route"`
	Workflow string     `json:"workflow"`
	Evidence []evidence `json:"evidence"`
}

type manifest struct {
	Contracts    map[string]string   `json:"contracts"`
	Capabilities map[string]coverage `json:"capabilities"`
	Operations   map[string]coverage `json:"operations"`
}

// Include the wire decoders as well as DTOs: query parameters and coercions are
// not fully described by OpenAPI. These explicit review tripwires cover both
// transports, model fields, and configuration schema. They are not generated
// coverage and must only be updated after reviewing UI behavior and its tests.
var contractFiles = []string{
	"internal/capabilities/catalog.go", "internal/capabilities/scopes.go", "internal/capabilities/errors.go",
	"internal/model/operation.go", "internal/model/spec.go", "internal/model/state.go", "internal/model/flow.go",
	"internal/app/types.go", "internal/control/rest/dto.go", "internal/control/rest/request.go",
	"internal/control/rest/flows.go", "internal/control/rest/handlers.go",
	"internal/control/mcp/dto.go", "internal/control/mcp/tools.go",
	"api/jsonschema/labmitm.dev.v1alpha1.json",
}

func main() {
	if err := check("."); err != nil {
		fmt.Fprintln(os.Stderr, "frontend parity:", err)
		os.Exit(1)
	}
	fmt.Println("Frontend registry, operation, contract, and evidence references match; web-test executes behavioral evidence.")
}

func check(root string) error {
	data, err := os.ReadFile(filepath.Join(root, "web/parity.json"))
	if err != nil {
		return err
	}
	var m manifest
	if err = json.Unmarshal(data, &m); err != nil {
		return err
	}
	ids := make([]string, 0, len(capabilities.All()))
	for _, c := range capabilities.All() {
		ids = append(ids, string(c.ID))
	}
	ops, err := operationNames(root)
	if err != nil {
		return err
	}
	return validate(root, m, ids, ops)
}

func operationNames(root string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, "internal/model/operation.go"), nil, 0)
	if err != nil {
		return nil, err
	}
	var names []string
	ast.Inspect(f, func(n ast.Node) bool {
		d, ok := n.(*ast.GenDecl)
		if !ok || d.Tok != token.CONST {
			return true
		}
		for _, spec := range d.Specs {
			v, ok := spec.(*ast.ValueSpec)
			if !ok || len(v.Names) != 1 || !strings.HasPrefix(v.Names[0].Name, "Op") || len(v.Values) != 1 {
				continue
			}
			if lit, ok := v.Values[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				name, err := strconv.Unquote(lit.Value)
				if err == nil {
					names = append(names, name)
				}
			}
		}
		return false
	})
	if len(names) == 0 {
		return nil, fmt.Errorf("no apply operation constants found")
	}
	return names, nil
}

func validate(root string, m manifest, ids, ops []string) error {
	for label, group := range map[string]struct {
		want []string
		got  map[string]coverage
	}{"capability": {ids, m.Capabilities}, "operation": {ops, m.Operations}} {
		for _, name := range group.want {
			c, ok := group.got[name]
			if !ok {
				return fmt.Errorf("missing %s %s", label, name)
			}
			if !strings.HasPrefix(c.Route, "/") || c.Workflow == "" || len(c.Evidence) == 0 {
				return fmt.Errorf("%s %s needs a route, workflow, and behavioral evidence", label, name)
			}
			for _, e := range c.Evidence {
				if e.Test == "" || !strings.HasPrefix(e.File, "src/") || !strings.Contains(e.File, ".test.") || strings.Contains(e.File, "..") {
					return fmt.Errorf("%s %s has invalid test evidence", label, name)
				}
				if _, err := os.Stat(filepath.Join(root, "web", e.File)); err != nil {
					return fmt.Errorf("%s %s evidence: %w", label, name, err)
				}
			}
		}
		for name := range group.got {
			if !slices.Contains(group.want, name) {
				return fmt.Errorf("unknown %s %s", label, name)
			}
		}
	}
	if len(m.Contracts) != len(contractFiles) {
		return fmt.Errorf("contract review files changed; review frontend inputs, outputs, and tests")
	}
	for _, file := range contractFiles {
		data, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			return err
		}
		if m.Contracts[file] != fmt.Sprintf("%x", sha256.Sum256(data)) {
			return fmt.Errorf("%s changed: review browser parity and behavioral tests before updating its web/parity.json digest", file)
		}
	}
	return nil
}

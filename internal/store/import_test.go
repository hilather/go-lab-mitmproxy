package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreImportDAG(t *testing.T) {
	fset := token.NewFileSet()
	forbidden := []string{
		"net/http",
		"net/smtp",
		"github.com/modelcontextprotocol",
		"github.com/hilather/go-lab-mitmproxy/internal/proxy",
		"github.com/hilather/go-lab-mitmproxy/internal/app",
		"github.com/hilather/go-lab-mitmproxy/internal/control",
		"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm",
		"github.com/hilather/go-lab-mitmproxy/internal/proxytest",
	}
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			ipath := strings.Trim(imp.Path.Value, `"`)
			for _, p := range forbidden {
				if ipath == p || strings.HasPrefix(ipath, p+"/") {
					t.Errorf("%s imports forbidden %q", path, ipath)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestStoreNoOutboundIdents(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		s := string(b)
		for _, bad := range []string{"net.Dial", "Dialer"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains %q", path, bad)
			}
		}
		f, err := parser.ParseFile(fset, path, b, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			name, ok := storeOutboundCallName(n)
			if ok {
				t.Errorf("%s references %s", path, name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

var storeOutboundSelectors = map[string]bool{
	"Dial": true, "DialTimeout": true, "DialContext": true,
}

func storeOutboundCallName(n ast.Node) (string, bool) {
	switch x := n.(type) {
	case *ast.SelectorExpr:
		if x.Sel != nil && storeOutboundSelectors[x.Sel.Name] {
			return x.Sel.Name, true
		}
	case *ast.CallExpr:
		id, ok := x.Fun.(*ast.Ident)
		if ok && storeOutboundSelectors[id.Name] {
			return id.Name, true
		}
	}
	return "", false
}

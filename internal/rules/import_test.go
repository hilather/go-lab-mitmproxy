package rules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRulesImportDAG(t *testing.T) {
	fset := token.NewFileSet()
	forbidden := []string{
		"net/http",
		"net/smtp",
		"github.com/modelcontextprotocol",
		"github.com/hilather/go-lab-mitmproxy/internal/compiler",
		"github.com/hilather/go-lab-mitmproxy/internal/app",
		"github.com/hilather/go-lab-mitmproxy/internal/control",
		"github.com/hilather/go-lab-mitmproxy/internal/proxy",
		"github.com/hilather/go-lab-mitmproxy/internal/tlsmitm",
		"github.com/hilather/go-lab-mitmproxy/internal/proxytest",
		"github.com/hilather/go-lab-mitmproxy/internal/store",
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

func TestRulesNoOutboundIdents(t *testing.T) {
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				switch fun := x.Fun.(type) {
				case *ast.SelectorExpr:
					if fun.Sel != nil {
						switch fun.Sel.Name {
						case "Dial", "DialTimeout", "DialContext":
							t.Errorf("%s references %s", name, fun.Sel.Name)
						}
					}
				case *ast.Ident:
					switch fun.Name {
					case "Dial", "DialTimeout", "DialContext":
						t.Errorf("%s references %s", name, fun.Name)
					}
				}
			case *ast.SelectorExpr:
				if x.Sel != nil && x.Sel.Name == "Dialer" {
					if id, ok := x.X.(*ast.Ident); ok && id.Name == "net" {
						t.Errorf("%s references net.Dialer", name)
					}
				}
			}
			return true
		})
	}
}

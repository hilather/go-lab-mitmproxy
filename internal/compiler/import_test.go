package compiler

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompilerImportDAG(t *testing.T) {
	fset := token.NewFileSet()
	forbidden := []string{
		"net/http",
		"net/smtp",
		"github.com/modelcontextprotocol",
		"github.com/hilather/go-lab-mitmproxy/internal/app",
		"github.com/hilather/go-lab-mitmproxy/internal/control",
		"github.com/hilather/go-lab-mitmproxy/internal/proxy",
		"github.com/hilather/go-lab-mitmproxy/internal/proxytest",
		"github.com/hilather/go-lab-mitmproxy/internal/store",
		"github.com/hilather/go-lab-mitmproxy/internal/audit",
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

func TestCompilerNoDialIdents(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				switch fun := x.Fun.(type) {
				case *ast.SelectorExpr:
					if fun.Sel != nil {
						switch fun.Sel.Name {
						case "Dial", "DialTimeout", "DialContext":
							t.Errorf("%s references %s", path, fun.Sel.Name)
						}
					}
				case *ast.Ident:
					switch fun.Name {
					case "Dial", "DialTimeout", "DialContext":
						t.Errorf("%s references %s", path, fun.Name)
					}
				}
			case *ast.SelectorExpr:
				if x.Sel != nil && x.Sel.Name == "Dialer" {
					if id, ok := x.X.(*ast.Ident); ok && id.Name == "net" {
						t.Errorf("%s references net.Dialer", path)
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

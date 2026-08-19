package tlsmitm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoDialIdents(t *testing.T) {
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
							t.Errorf("%s references %s (tlsmitm must not Dial)", name, fun.Sel.Name)
						}
					}
				case *ast.Ident:
					switch fun.Name {
					case "Dial", "DialTimeout", "DialContext":
						t.Errorf("%s references %s (tlsmitm must not Dial)", name, fun.Name)
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

func testdataTLS(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		p := filepath.Join(dir, "testdata", "tls", name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("testdata/tls/%s not found", name)
		}
		dir = parent
	}
}

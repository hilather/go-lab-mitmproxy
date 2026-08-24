package wsx

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
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
						case "Dial", "DialTimeout", "DialContext", "DialUDP", "ListenUDP", "ListenPacket":
							t.Errorf("%s references %s (wsx must not Dial or listen)", name, fun.Sel.Name)
						}
					}
				case *ast.Ident:
					switch fun.Name {
					case "Dial", "DialTimeout", "DialContext", "DialUDP", "ListenUDP", "ListenPacket":
						t.Errorf("%s references %s (wsx must not Dial or listen)", name, fun.Name)
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

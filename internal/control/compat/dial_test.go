package compat

import (
	"go/ast"
	"go/token"
	"testing"
)

func astInspectDial(t *testing.T, fset *token.FileSet, path string, f *ast.File) {
	t.Helper()
	ast.Inspect(f, func(n ast.Node) bool {
		id, ok := dialIdent(n)
		if ok {
			t.Errorf("%s:%s references %s (compat must not Dial)", path, fset.Position(n.Pos()), id)
		}
		return true
	})
}

func dialIdent(n ast.Node) (string, bool) {
	switch x := n.(type) {
	case *ast.SelectorExpr:
		if x.Sel == nil {
			return "", false
		}
		switch x.Sel.Name {
		case "Dial", "DialTimeout", "DialContext":
			return x.Sel.Name, true
		case "Dialer":
			if id, ok := x.X.(*ast.Ident); ok && id.Name == "net" {
				return "net.Dialer", true
			}
		}
	case *ast.Ident:
		switch x.Name {
		case "Dial", "DialTimeout", "DialContext":
			return x.Name, true
		}
	}
	return "", false
}

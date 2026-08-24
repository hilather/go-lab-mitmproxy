package proxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDialIsolation walks production internal/* files. Dial / DialTimeout /
// DialContext / net.Dialer / DialUDP / ListenUDP / ListenPacket are allowed
// only in internal/proxy and internal/proxytest (D16, D68). net.Listen is
// not forbidden (control-plane binds).
func TestDialIsolation(t *testing.T) {
	root := moduleRoot(t)
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" || name == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(mustRel(root, path))
		if allowedDialFile(rel) {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			name, ok := outboundCallName(n)
			if ok {
				t.Errorf("%s references %s (Dial is isolated to internal/proxy)", rel, name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func allowedDialFile(rel string) bool {
	return strings.HasPrefix(rel, "internal/proxy/") || strings.HasPrefix(rel, "internal/proxytest/")
}

func outboundCallName(n ast.Node) (string, bool) {
	switch x := n.(type) {
	case *ast.CallExpr:
		switch fun := x.Fun.(type) {
		case *ast.SelectorExpr:
			if fun.Sel != nil && callSelectors[fun.Sel.Name] {
				return fun.Sel.Name, true
			}
		case *ast.Ident:
			if callSelectors[fun.Name] {
				return fun.Name, true
			}
		}
	case *ast.SelectorExpr:
		if x.Sel != nil && x.Sel.Name == "Dialer" {
			if id, ok := x.X.(*ast.Ident); ok && id.Name == "net" {
				return "net.Dialer", true
			}
		}
	}
	return "", false
}

var callSelectors = map[string]bool{
	"Dial": true, "DialTimeout": true, "DialContext": true,
	// D68: UDP Dial/listen stay in internal/proxy. Do not forbid net.Listen
	// (management REST and metrics already bind in production).
	"ListenPacket": true, "ListenUDP": true, "DialUDP": true,
}

func mustRel(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

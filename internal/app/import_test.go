package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppImportDAG(t *testing.T) {
	fset := token.NewFileSet()
	forbidden := []string{
		"net/http",
		"net/smtp",
		"github.com/modelcontextprotocol",
		"github.com/hilather/go-lab-mitmproxy/internal/control",
		"github.com/hilather/go-lab-mitmproxy/internal/proxy",
		"github.com/hilather/go-lab-mitmproxy/internal/proxytest",
		"github.com/hilather/go-lab-mitmproxy/internal/web",
	}
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
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
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(src)
		if strings.Contains(text, "net.Dial") || strings.Contains(text, "Dialer") {
			t.Errorf("%s contains a forbidden outbound ident", path)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if x.Sel != nil && (x.Sel.Name == "Dial" || x.Sel.Name == "DialTimeout" || x.Sel.Name == "DialContext") {
					t.Errorf("%s references %s", path, x.Sel.Name)
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

func TestServiceHasNoInsert(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "service.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name.Name != "Service" {
				continue
			}
			iface, ok := ts.Type.(*ast.InterfaceType)
			if !ok {
				t.Fatal("Service is not an interface")
			}
			for _, m := range iface.Methods.List {
				for _, n := range m.Names {
					if n.Name == "Insert" {
						t.Fatal("proxy insert must stay off Service")
					}
				}
			}
		}
	}
}

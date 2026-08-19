package observability

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportDAG(t *testing.T) {
	fset := token.NewFileSet()
	forbiddenPref := []string{
		"github.com/prometheus",
		"go.opentelemetry.io",
		"github.com/modelcontextprotocol",
		"net/smtp",
		"github.com/hilather/go-lab-mitmproxy/internal/",
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
			for _, p := range forbiddenPref {
				if ipath == p || strings.HasPrefix(ipath, p) {
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

package rest

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRESTImportDAG(t *testing.T) {
	fset := token.NewFileSet()
	allowed := map[string]bool{
		"github.com/hilather/go-lab-mitmproxy/internal/app":           true,
		"github.com/hilather/go-lab-mitmproxy/internal/audit":         true,
		"github.com/hilather/go-lab-mitmproxy/internal/auth":          true,
		"github.com/hilather/go-lab-mitmproxy/internal/buildinfo":     true,
		"github.com/hilather/go-lab-mitmproxy/internal/capabilities":  true,
		"github.com/hilather/go-lab-mitmproxy/internal/config":        true,
		"github.com/hilather/go-lab-mitmproxy/internal/domainerr":     true,
		"github.com/hilather/go-lab-mitmproxy/internal/model":         true,
		"github.com/hilather/go-lab-mitmproxy/internal/observability": true,
		"github.com/hilather/go-lab-mitmproxy/internal/store":         true, // ResumePatch on Service
	}
	forbiddenPref := []string{
		"github.com/modelcontextprotocol",
		"github.com/hilather/go-lab-mitmproxy/internal/compiler",
		"github.com/hilather/go-lab-mitmproxy/internal/proxy",
		"github.com/hilather/go-lab-mitmproxy/internal/control/mcp",
		"github.com/hilather/go-lab-mitmproxy/internal/web",
		"net/smtp",
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
				if ipath == p || strings.HasPrefix(ipath, p+"/") {
					t.Errorf("%s imports forbidden %q", path, ipath)
				}
			}
			if strings.HasPrefix(ipath, "github.com/hilather/go-lab-mitmproxy/internal/") && !allowed[ipath] {
				t.Errorf("%s production import %q", path, ipath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

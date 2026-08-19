package web

import (
	"embed"
	"io/fs"
)

//go:embed all:stub
var stub embed.FS

// Files returns the committed stub used by go test before web-build.
// UI-001 copies the production Vite tree into dist/.
func Files() fs.FS {
	sub, err := fs.Sub(stub, "stub")
	if err != nil {
		return stub
	}
	return sub
}

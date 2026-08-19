// Command labmitm is the LabMITM process entrypoint.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/hilather/go-lab-mitmproxy/internal/buildinfo"
)

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		printUsage(stderr)
		return 2
	}
	switch args[1] {
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	case "version", "-v", "--version":
		_, _ = fmt.Fprintln(stdout, buildinfo.Current().String())
		return 0
	case "serve", "validate", "canonicalize", "healthcheck", "mcp-stdio":
		_, _ = fmt.Fprintf(stderr, "labmitm %s is not implemented yet\n", args[1])
		return 2
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n", args[1])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	_, _ = io.WriteString(w, usageText)
}

const usageText = `usage: labmitm <command>

LabMITM is a laboratory HTTP(S) intercepting proxy. This binary is a
foundation stub: only version and help are implemented. Proxy, TLS,
store, REST, and MCP are not bound yet.

Commands:
  version    print build and protocol metadata
  help       print this help

Planned (not implemented):
  serve           load YAML and bind proxy + management
  validate        fail-closed YAML check
  canonicalize    emit canonical spec
  healthcheck     probe GET /v1/health/ready
  mcp-stdio       Streamable MCP over stdio
`

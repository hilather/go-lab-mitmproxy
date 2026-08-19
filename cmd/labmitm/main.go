// Command labmitm is the LabMITM process entrypoint.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

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
	case "validate":
		return validateCmd(args[2:], stdout, stderr)
	case "canonicalize":
		return canonicalizeCmd(args[2:], stdout, stderr)
	case "serve":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return serveCmd(ctx, args[2:], stdout, stderr)
	case "healthcheck", "mcp-stdio":
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

LabMITM is a laboratory HTTP(S) intercepting proxy. validate and
canonicalize load a fail-closed labmitm.dev/v1alpha1 document. serve
binds the HTTP/1.1 forward proxy (tls.intercept is a data-plane
knob, not a second listener). Management REST /v1 binds only when
--management-listen is an address and bearer auth has ≥1 token.

Commands:
  version         print build and protocol metadata
  help            print this help
  validate        fail-closed YAML check (--config)
  canonicalize    emit canonical spec (--config, --format yaml|json)
  serve           load YAML and bind the proxy (--config, --proxy-listen,
                  --management-listen, --shutdown-timeout, --pid-file)

Planned (not implemented):
  healthcheck     probe GET /v1/health/ready
  mcp-stdio       Streamable MCP over stdio
`

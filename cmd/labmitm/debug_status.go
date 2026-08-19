package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// debugStatusCmd prints Uid/CapEff from /proc/self/status so the scratch
// image can prove identity without a shell. --check-readonly fails if the
// process can create /probe-ro (read-only root contract).
// --check-system-certs fails unless the copied CA bundle exists and
// x509.SystemCertPool() is non-empty (upstream verify contract).
func debugStatusCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("debug-status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	checkRO := fs.Bool("check-readonly", false, "fail if / is writable")
	checkPool := fs.Bool("check-system-certs", false, "fail if SystemCertPool is empty")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	body, err := os.ReadFile("/proc/self/status")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "labmitm debug-status: %v\n", err)
		return 1
	}
	var uid, capeef string
	for _, line := range strings.Split(string(body), "\n") {
		switch {
		case strings.HasPrefix(line, "Uid:"):
			uid = line
			_, _ = fmt.Fprintln(stdout, line)
		case strings.HasPrefix(line, "CapEff:"):
			capeef = line
			_, _ = fmt.Fprintln(stdout, line)
		}
	}
	if uid == "" || capeef == "" {
		_, _ = fmt.Fprintln(stderr, "labmitm debug-status: missing Uid or CapEff")
		return 1
	}
	if *checkPool {
		const bundle = "/etc/ssl/certs/ca-certificates.crt"
		if st, err := os.Stat(bundle); err != nil || st.Size() == 0 {
			_, _ = fmt.Fprintf(stderr, "labmitm debug-status: missing or empty %s\n", bundle)
			return 1
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "labmitm debug-status: SystemCertPool: %v\n", err)
			return 1
		}
		if pool == nil || pool.Equal(x509.NewCertPool()) {
			_, _ = fmt.Fprintln(stderr, "labmitm debug-status: SystemCertPool is empty")
			return 1
		}
		_, _ = fmt.Fprintln(stdout, "SystemCertPool: non-empty")
	}
	if !*checkRO {
		return 0
	}
	f, err := os.OpenFile("/probe-ro", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		_ = f.Close()
		_ = os.Remove("/probe-ro")
		_, _ = fmt.Fprintln(stderr, "labmitm debug-status: wrote /probe-ro (root is writable)")
		return 1
	}
	return 0
}

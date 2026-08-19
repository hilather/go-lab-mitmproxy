package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/proxy"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

type serveFlags struct {
	Config           string
	ProxyListen      string
	ManagementListen string
	ShutdownTimeout  time.Duration
	PIDFile          string
}

func parseServeFlags(args []string, stderr io.Writer) (serveFlags, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "path to bootstrap YAML or JSON")
	proxyListen := fs.String("proxy-listen", "", "override proxy listen address (empty uses YAML)")
	mgmtListen := fs.String("management-listen", "off", "override management listen address; off/none/- leaves it unbound")
	shutdown := fs.Duration("shutdown-timeout", proxy.DefaultShutdownWait, "graceful shutdown deadline")
	pidFile := fs.String("pid-file", "", "write process id after listeners bind")
	if err := fs.Parse(args); err != nil {
		return serveFlags{}, err
	}
	if *path == "" {
		_, _ = fmt.Fprintln(stderr, "labmitm serve: --config is required")
		return serveFlags{}, fmt.Errorf("missing --config")
	}
	return serveFlags{
		Config:           *path,
		ProxyListen:      *proxyListen,
		ManagementListen: *mgmtListen,
		ShutdownTimeout:  *shutdown,
		PIDFile:          *pidFile,
	}, nil
}

func serveCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags, err := parseServeFlags(args, stderr)
	if err != nil {
		return 2
	}
	rt, err := serveFromConfig(ctx, flags)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "labmitm serve: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "labmitm proxy listen=%s\n", rt.proxy.Addr().String())
	_, _ = fmt.Fprintln(stdout, "labmitm management: not bound")
	<-ctx.Done()
	deadline := flags.ShutdownTimeout
	if deadline <= 0 {
		deadline = proxy.DefaultShutdownWait
	}
	shctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	_ = rt.shutdown(shctx)
	_, _ = fmt.Fprintln(stdout, "labmitm: shutting down")
	return 0
}

type serveRuntime struct {
	proxy   *proxy.Server
	store   *store.Memory
	pidPath string
}

func serveFromConfig(ctx context.Context, flags serveFlags) (*serveRuntime, error) {
	_ = ctx
	st, err := config.LoadFile(flags.Config)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", flags.Config, err)
	}
	if !managementOff(flags.ManagementListen) {
		return nil, fmt.Errorf("management listener requires API-001 (no verifier); use --management-listen=off")
	}
	addr := st.Spec.Listeners.Proxy.Address
	if flags.ProxyListen != "" {
		addr = flags.ProxyListen
	}
	inbox, err := store.New(store.OptionsFromSpec(st.Spec.Store))
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	srv, err := proxy.New(proxy.Options{
		Address: addr,
		Spec:    st.Spec,
		Sink:    proxy.AdaptStore(inbox),
	})
	if err != nil {
		inbox.Wipe()
		return nil, err
	}
	if err := srv.Start(); err != nil {
		inbox.Wipe()
		return nil, err
	}
	if err := writePIDFile(flags.PIDFile); err != nil {
		_ = srv.Shutdown(context.Background())
		inbox.Wipe()
		return nil, fmt.Errorf("pid-file: %w", err)
	}
	return &serveRuntime{proxy: srv, store: inbox, pidPath: flags.PIDFile}, nil
}

func managementOff(flagAddr string) bool {
	switch strings.ToLower(strings.TrimSpace(flagAddr)) {
	case "", "off", "none", "-":
		return true
	default:
		return false
	}
}

func (r *serveRuntime) shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	var first error
	if r.proxy != nil {
		first = r.proxy.Shutdown(ctx)
	}
	if r.store != nil {
		r.store.Wipe()
	}
	if r.pidPath != "" {
		_ = os.Remove(r.pidPath)
	}
	return first
}

func writePIDFile(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

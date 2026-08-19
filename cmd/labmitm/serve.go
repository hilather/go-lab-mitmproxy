package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/auth"
	"github.com/hilather/go-lab-mitmproxy/internal/control/rest"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/proxy"
	"github.com/hilather/go-lab-mitmproxy/internal/web"
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
	if rt.http == nil {
		_, _ = fmt.Fprintln(stdout, "labmitm management: not bound")
	} else {
		_, _ = fmt.Fprintf(stdout, "labmitm management listen=%s\n", rt.http.Addr())
	}
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
	http    *rest.Server
	svc     *app.App
	pidPath string
}

func serveFromConfig(ctx context.Context, flags serveFlags) (*serveRuntime, error) {
	svc, err := app.Boot(ctx, app.Options{BootstrapPath: flags.Config})
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", flags.Config, err)
	}
	snap := svc.Active()
	if snap == nil || snap.Canonical == nil {
		svc.Close()
		return nil, fmt.Errorf("compile %s: no snapshot", flags.Config)
	}
	addr := snap.Canonical.Spec.Listeners.Proxy.Address
	if flags.ProxyListen != "" {
		addr = flags.ProxyListen
	}
	srv, err := proxy.New(proxy.Options{
		Address:   addr,
		Spec:      snap.Canonical.Spec,
		Sink:      proxy.AdaptStore(svc.Inbox()),
		Store:     svc.Inbox(),
		Snapshots: svc.Snapshots(),
		Authority: snap.CA,
	})
	if err != nil {
		svc.Close()
		return nil, err
	}
	if err := srv.Start(); err != nil {
		svc.Close()
		return nil, err
	}
	svc.SetReplay(srv.Replay)
	rt := &serveRuntime{proxy: srv, svc: svc, pidPath: flags.PIDFile}
	mgmt, unbound := managementListen(flags.ManagementListen, snap.Canonical.Spec.Listeners.Management.Address)
	if !unbound {
		hs, err := startManagement(svc, mgmt, snap.Canonical.Spec)
		if err != nil {
			_ = srv.Shutdown(context.Background())
			svc.Close()
			return nil, err
		}
		rt.http = hs
	}
	svc.SetHealth(func() app.HealthFacts {
		return app.HealthFacts{
			ProxyBound: srv.Accepting(),
			StoreUp:    svc.Inbox() != nil,
			MgmtBound:  rt.http != nil,
			MgmtOff:    unbound,
		}
	})
	if err := writePIDFile(flags.PIDFile); err != nil {
		_ = rt.shutdown(context.Background())
		return nil, fmt.Errorf("pid-file: %w", err)
	}
	return rt, nil
}

func startManagement(svc *app.App, addr string, spec model.Spec) (*rest.Server, error) {
	if addr == "" {
		addr = rest.DefaultAddr
	}
	verifier, err := auth.FromSpec(spec.Management.Auth)
	if err != nil {
		return nil, err
	}
	if err := verifier.RequireListen(); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	hs, err := rest.New(rest.Config{
		Addr:           addr,
		Service:        svc,
		AllowedOrigins: spec.Management.OriginAllowlist,
		MaxBodyBytes:   spec.Management.BodyLimit,
		MaxConcurrent:  spec.Management.MaxConcurrent,
		RatePerSec:     float64(spec.Management.RequestsPerSecond),
		RateBurst:      float64(spec.Management.Burst),
		PublicMetrics:  spec.Observability.Metrics.PublicPath,
		Auth:           verifier,
		CookieSecure:   spec.Listeners.Management.TLS.Enabled,
		UI:             web.NewHandler(nil),
		UIEnabled: func() bool {
			snap := svc.Active()
			if snap == nil || snap.Canonical == nil {
				return spec.UI.Enabled
			}
			return snap.Canonical.Spec.UI.Enabled
		},
	})
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	hs.Attach(ln)
	go func() { _ = hs.Serve(ln) }()
	return hs, nil
}

func managementListen(flagAddr, yamlAddr string) (addr string, unbound bool) {
	switch strings.ToLower(strings.TrimSpace(flagAddr)) {
	case "off", "none", "-":
		return "", true
	case "":
		if yamlAddr == "" {
			yamlAddr = rest.DefaultAddr
		}
		return yamlAddr, false
	default:
		return strings.TrimSpace(flagAddr), false
	}
}

func (r *serveRuntime) shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	var first error
	if r.http != nil {
		first = r.http.Shutdown(ctx)
	}
	if r.proxy != nil {
		if err := r.proxy.Shutdown(ctx); err != nil && first == nil {
			first = err
		}
	}
	if r.svc != nil {
		r.svc.Close()
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

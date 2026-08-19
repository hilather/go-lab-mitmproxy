package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/auth"
	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/control/mcp"
	"github.com/hilather/go-lab-mitmproxy/internal/control/rest"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/observability"
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
	if rt.metrics != nil && rt.metrics.Addr() != "" {
		_, _ = fmt.Fprintf(stdout, "labmitm metrics listen=%s\n", rt.metrics.Addr())
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
	proxy    *proxy.Server
	http     *rest.Server
	mcp      *mcp.Server
	svc      *app.App
	metrics  *observability.Listener
	stopLogs context.CancelFunc
	pidPath  string
}

func serveFromConfig(ctx context.Context, flags serveFlags) (*serveRuntime, error) {
	st, err := config.LoadFile(flags.Config)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", flags.Config, err)
	}
	reg := observability.NewRegistry()
	log := observability.NewLogger(os.Stderr, observability.ParseLevel(st.Spec.Observability.LogLevel)).
		WithQueue(observability.DefaultQueueSize).WithMetrics(reg)
	logCtx, stopLogs := context.WithCancel(context.Background())
	go log.Serve(logCtx)
	svc, err := app.Boot(ctx, app.Options{
		BootstrapPath: flags.Config,
		Metrics:       reg,
		Logger:        log,
	})
	if err != nil {
		stopLogs()
		return nil, fmt.Errorf("load %s: %w", flags.Config, err)
	}
	snap := svc.Active()
	if snap == nil || snap.Canonical == nil {
		stopLogs()
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
		Metrics:   reg,
		Logger:    log,
	})
	if err != nil {
		stopLogs()
		svc.Close()
		return nil, err
	}
	if err := srv.Start(); err != nil {
		stopLogs()
		svc.Close()
		return nil, err
	}
	svc.SetReplay(srv.Replay)
	rt := &serveRuntime{proxy: srv, svc: svc, stopLogs: stopLogs, pidPath: flags.PIDFile}
	mgmt, unbound := managementListen(flags.ManagementListen, snap.Canonical.Spec.Listeners.Management.Address)
	if !unbound {
		hs, mcpSrv, err := startManagement(svc, mgmt, snap.Canonical.Spec, reg, log)
		if err != nil {
			_ = rt.shutdown(context.Background())
			return nil, err
		}
		rt.http = hs
		rt.mcp = mcpSrv
	}
	svc.SetHealth(func() observability.Facts {
		return observability.Facts{
			ProxyBound: srv.Accepting(),
			StoreUp:    svc.Inbox() != nil,
			MgmtBound:  rt.http != nil,
			MgmtOff:    unbound,
		}
	})
	ml, err := observability.Listen(snap.Canonical.Spec.Observability.Metrics.Listen, reg)
	if err != nil {
		_ = rt.shutdown(context.Background())
		return nil, fmt.Errorf("metrics listen: %w", err)
	}
	rt.metrics = ml
	if err := writePIDFile(flags.PIDFile); err != nil {
		_ = rt.shutdown(context.Background())
		return nil, fmt.Errorf("pid-file: %w", err)
	}
	return rt, nil
}

func startManagement(svc *app.App, addr string, spec model.Spec, reg *observability.Registry, log *observability.Logger) (*rest.Server, *mcp.Server, error) {
	if addr == "" {
		addr = rest.DefaultAddr
	}
	verifier, err := auth.FromSpec(spec.Management.Auth)
	if err != nil {
		return nil, nil, err
	}
	if err := verifier.RequireListen(); err != nil {
		return nil, nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	mcpPath := spec.Listeners.Management.MCPPath
	if mcpPath == "" {
		mcpPath = mcp.DefaultPath
	}
	mcpSrv, err := mcp.New(mcp.Config{
		Service:            svc,
		AllowedOrigins:     spec.Management.OriginAllowlist,
		AllowLegacyClients: spec.Management.MCP.AllowLegacyClients,
		MaxBodyBytes:       spec.Management.BodyLimit,
		MaxConcurrent:      spec.Management.MaxConcurrent,
		RatePerSec:         float64(spec.Management.RequestsPerSecond),
		RateBurst:          float64(spec.Management.Burst),
		Auth:               verifier,
	})
	if err != nil {
		_ = ln.Close()
		return nil, nil, err
	}
	ready := func() bool {
		return observability.Evaluate(svc.HealthFacts()).Ready
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
		Metrics:        reg,
		Logger:         log,
		Ready:          ready,
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
		Mounts: map[string]http.Handler{mcpPath: mcpSrv.Handler()},
	})
	if err != nil {
		mcpSrv.Close()
		_ = ln.Close()
		return nil, nil, err
	}
	hs.Attach(ln)
	go func() { _ = hs.Serve(ln) }()
	return hs, mcpSrv, nil
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
	if r.mcp != nil {
		r.mcp.Close()
	}
	// Proxy first so ready goes unready as soon as Shutdown begins.
	if r.proxy != nil {
		first = r.proxy.Shutdown(ctx)
	}
	if r.http != nil {
		if err := r.http.Shutdown(ctx); err != nil && first == nil {
			first = err
		}
	}
	if r.metrics != nil {
		if err := r.metrics.Shutdown(ctx); err != nil && first == nil {
			first = err
		}
	}
	if r.svc != nil {
		r.svc.Close()
	}
	if r.stopLogs != nil {
		r.stopLogs()
		r.stopLogs = nil
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

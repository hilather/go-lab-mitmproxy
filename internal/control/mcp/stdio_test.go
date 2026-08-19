package mcp

import (
	"context"
	"io"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestStdioDevAdapterSameRegistry(t *testing.T) {
	s, _ := newTestServer(t)
	pr1, pw1 := io.Pipe()
	pr2, pw2 := io.Pipe()
	t.Cleanup(func() {
		_ = pr1.Close()
		_ = pw1.Close()
		_ = pr2.Close()
		_ = pw2.Close()
	})
	ctx := t.Context()
	errc := make(chan error, 1)
	go func() {
		errc <- s.run(ctx, &sdk.IOTransport{Reader: pr1, Writer: pw2})
	}()
	client := sdk.NewClient(&sdk.Implementation{Name: "stdio-test", Version: "dev"}, nil)
	cs, err := client.Connect(ctx, &sdk.IOTransport{Reader: pr2, Writer: pw1}, nil)
	if err != nil {
		t.Fatalf("stdio connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	seen := map[string]bool{}
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		seen[tool.Name] = true
	}
	if !seen["mitm_version_get"] || !seen["mitm_change_apply"] {
		t.Fatalf("stdio missing core tools: %v", seen)
	}
	res := callTool(t, cs, "mitm_version_get", map[string]any{})
	if res.IsError {
		t.Fatalf("stdio version: %+v", res)
	}
}

func TestStdioLogsAreNotStdout(t *testing.T) {
	s, _ := newTestServer(t)
	if s.sdk == nil {
		t.Fatal("missing sdk server")
	}
}

func TestStdioListenURIOnlyNotify(t *testing.T) {
	s, svc := newTestServer(t)
	pr1, pw1 := io.Pipe()
	pr2, pw2 := io.Pipe()
	t.Cleanup(func() {
		_ = pr1.Close()
		_ = pw1.Close()
		_ = pr2.Close()
		_ = pw2.Close()
	})
	ctx := t.Context()
	errc := make(chan error, 1)
	go func() {
		errc <- s.run(ctx, &sdk.IOTransport{Reader: pr1, Writer: pw2})
	}()
	got := make(chan string, 1)
	client := sdk.NewClient(&sdk.Implementation{Name: "stdio-listen", Version: "dev"}, &sdk.ClientOptions{
		ResourceUpdatedHandler: func(_ context.Context, req *sdk.ResourceUpdatedNotificationRequest) {
			if req != nil && req.Params != nil {
				select {
				case got <- req.Params.URI:
				default:
				}
			}
		},
	})
	cs, err := client.Connect(ctx, &sdk.IOTransport{Reader: pr2, Writer: pw1}, nil)
	if err != nil {
		t.Fatalf("stdio connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	if err := cs.Subscribe(ctx, &sdk.SubscribeParams{URI: resourceFlows}); err != nil {
		t.Fatalf("stdio subscribe: %v", err)
	}
	// Wait for the listen stream to register before the first insert.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		insertFlow(t, svc, "stdio-listen.lab")
		select {
		case uri := <-got:
			if uri != resourceFlows {
				t.Fatalf("stdio updated uri=%q", uri)
			}
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("stdio listen stayed silent; expected URI-only resources/updated")
}

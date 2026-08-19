# LabMITM task runner. Tool versions are pinned; do not use @latest.

GO ?= go
export GOTOOLCHAIN ?= local
export GOPROXY ?= https://proxy.golang.org,direct

GOLANGCI_LINT_VERSION ?= v2.12.2
GOVULNCHECK_MOD ?= golang.org/x/vuln/cmd/govulncheck@v1.1.4
GOLANGCI_LINT_MOD ?= github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: help fmt format lint vet build generate verify-generated test test-race \
	test-fuzz-smoke test-parity test-config-compat test-docs test-container \
	security-scan test-changelog web-test web-build

help:
	@printf '%s\n' \
		'LabMITM Make targets (Go 1.26; module github.com/hilather/go-lab-mitmproxy)' \
		'  format              go fmt ./...' \
		'  fmt                 alias for format' \
		'  vet                 go vet ./...' \
		'  lint                go vet + golangci-lint $(GOLANGCI_LINT_VERSION)' \
		'  build               go build -o bin/labmitm ./cmd/labmitm' \
		'  generate            write api/capabilities/v1.json, api/openapi/v1.json, api/mcp/v1.json, api/metrics/v1alpha1.json' \
		'  verify-generated    fail if generate would change those files' \
		'  test                go test ./...' \
		'  test-race           go test -race ./...' \
		'  test-fuzz-smoke     buildinfo + config FuzzDecode seed corpora (5s each)' \
		'  test-docs           required documents, metadata, and links' \
		'  security-scan       govulncheck' \
		'  test-parity         REST/MCP capability parity and MCP goldens' \
		'  test-config-compat  positive+negative v1alpha1 config fixtures' \
		'  web-test            unimplemented until UI-001 (PR 13); fail-closed' \
		'  web-build           unimplemented until UI-001 (PR 13); fail-closed' \
		'  test-container      unimplemented until DEP-001 (PR 12); fail-closed' \
		'  test-changelog      unimplemented until GA-001 (PR 14); fail-closed'

fmt: format

format:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

lint: vet
	$(GO) run $(GOLANGCI_LINT_MOD) run ./...

build:
	$(GO) build -o bin/labmitm ./cmd/labmitm

generate:
	$(GO) run ./scripts/generate

verify-generated:
	$(GO) run ./scripts/generate -check

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

test-fuzz-smoke:
	$(GO) test ./internal/buildinfo -fuzz=FuzzInfoString -fuzztime=5s -count=1
	$(GO) test ./internal/config -fuzz=FuzzDecode -fuzztime=5s -count=1

test-docs:
	$(GO) run ./scripts/checkdocs

security-scan:
	$(GO) run $(GOVULNCHECK_MOD) ./...

test-parity:
	$(GO) test ./internal/capabilities ./internal/control/rest ./internal/control/mcp -count=1

test-config-compat:
	$(GO) test ./internal/config -run TestConfigCompat -count=1

web-test:
	@echo 'web-test: unimplemented until UI-001 (PR 13)' >&2; exit 1

web-build:
	@echo 'web-build: unimplemented until UI-001 (PR 13)' >&2; exit 1

test-container:
	@echo 'test-container: unimplemented until DEP-001 (PR 12)' >&2; exit 1

test-changelog:
	@echo 'test-changelog: unimplemented until a checkchangelog script lands' >&2; exit 1

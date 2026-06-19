# graverobber Makefile — build, test, and MCP targets.
#
# The MCP targets (mcp, mcp-test, mcp-inspect) front the graverobber-mcp server,
# the Model Context Protocol adapter over graverobber's engine (necromancer-mcp
# packet P20-01). The CLI and the MCP server share pkg/scanner, pkg/verifier,
# and pkg/fingerprints — one engine, two front ends.

GO ?= go
CGO_ENABLED ?= 0
BINDIR ?= bin
MCP_BIN := $(BINDIR)/graverobber-mcp
CLI_BIN := $(BINDIR)/graverobber

.PHONY: all build test vet fmt-check mcp mcp-test mcp-inspect clean

all: build

## build: build the graverobber CLI and the graverobber-mcp server.
build:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -o $(CLI_BIN) ./cmd/graverobber
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -o $(MCP_BIN) ./cmd/graverobber-mcp

## test: run the full module test suite (serial packages keep timing-sensitive
## scanner tests deterministic).
test:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -p 1 -timeout 300s ./...

## vet: run go vet across the module.
vet:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) vet ./...

## fmt-check: fail if any file is not gofmt-clean.
fmt-check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi

## mcp: build only the graverobber-mcp server binary onto PATH (bin/).
mcp:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -o $(MCP_BIN) ./cmd/graverobber-mcp
	@echo "built $(MCP_BIN)"

## mcp-test: run the MCP server's three test tiers — protocol conformance +
## detect->confirm smoke (in-process), the active-gating + stdout-clean unit
## tests, and the shared nmc library tests. Headless: no GUI, no network egress
## required, in-memory transport for the smoke run.
mcp-test:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -timeout 180s ./cmd/graverobber-mcp/... ./internal/nmc/...

## mcp-inspect: launch the MCP Inspector against the server (interactive UI).
## Requires Node 22+. The CLI form below lists tools and exits non-zero on
## failure — wire it into CI for a conformance snapshot.
mcp-inspect: mcp
	npx @modelcontextprotocol/inspector -- $(MCP_BIN)

## mcp-inspect-cli: scripted Inspector conformance (tools/list), non-interactive.
mcp-inspect-cli: mcp
	npx @modelcontextprotocol/inspector --cli $(MCP_BIN) --method tools/list

clean:
	rm -rf $(BINDIR)

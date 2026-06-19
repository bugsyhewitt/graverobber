# graverobber — Makefile
#
# Build, test, and database-refresh targets. The takeover-confirmation feature
# (Packet 07) adds fpdb-sync; the rest mirror the standard Go workflow the repo
# already uses (go build / go test / go vet).

.DEFAULT_GOAL := build

BIN_DIR := bin

.PHONY: build
build: ## build the graverobber CLI
	go build -o $(BIN_DIR)/graverobber ./cmd/graverobber

.PHONY: test
test: ## unit tests incl. multi-signal precision + confirm/release (no network needed)
	go test ./...

.PHONY: vet
vet: ## go vet the whole module
	go vet ./...

.PHONY: fpdb-sync
fpdb-sync: ## refresh the vendored fingerprint DB from can-i-take-over-xyz (D1)
	bash scripts/fpdb-sync.sh

.PHONY: confirm-demo
confirm-demo: build ## safe dry-run see-it-work: detect-shape -> claim -> serve canary -> prove -> release (no provider touched)
	@echo "graverobber confirm-takeover (DRY-RUN) against an owned-style target:"
	$(BIN_DIR)/graverobber confirm-takeover --target assets.example.com --service github-pages --authorized --allow-apex example.com --json || true

.PHONY: clean
clean: ## remove build artifacts
	rm -rf $(BIN_DIR)

.PHONY: help
help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

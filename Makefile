# Makefile for github.com/dogadmin/jsscango
#
# Common workflows:
#   make            # show this help
#   make build      # build ./bin/jsscango for the host platform
#   make test       # run unit tests
#   make release    # cross-compile binaries into ./dist

# VERSION is embedded into the binary via -ldflags -X main.version=...
# Falls back to "dev" when git is unavailable or this isn't a checkout.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Common build flags. Quoting $(VERSION) so spaces in commit messages
# (e.g. from --dirty annotations) don't split the ldflags arg.
LDFLAGS := -s -w -X 'main.version=$(VERSION)'
GOFLAGS := -trimpath -ldflags="$(LDFLAGS)"

PKG     := ./cmd/getjsurlscan
BIN     := jsscango
BIN_DIR := bin
DIST    := dist

# Cross-compile matrix for `release`.
RELEASE_TARGETS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

.DEFAULT_GOAL := help

.PHONY: help build test race bench vet lint tidy install release clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "; printf "Usage: make <target>\n\nTargets:\n"} \
		/^[a-zA-Z_-]+:.*?## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the binary into ./bin/jsscango
	@mkdir -p $(BIN_DIR)
	go build $(GOFLAGS) -o $(BIN_DIR)/$(BIN) $(PKG)

test: ## Run unit tests
	go test ./...

race: ## Run tests with the race detector
	go test -race ./...

bench: ## Run benchmarks (no tests)
	go test -bench=. -benchmem -run=^$$ ./...

vet: ## Run go vet
	go vet ./...

lint: ## Check that all Go files are gofmt'd (fails on unformatted files)
	@gofmt -l . | tee /dev/stderr | (! read)

tidy: ## Run go mod tidy
	go mod tidy

install: ## Install the binary into $$GOBIN / $$GOPATH/bin
	go install $(GOFLAGS) $(PKG)

release: ## Cross-compile release binaries into ./dist
	@mkdir -p $(DIST)
	@for target in $(RELEASE_TARGETS); do \
		goos=$${target%/*}; \
		goarch=$${target#*/}; \
		ext=""; \
		if [ "$$goos" = "windows" ]; then ext=".exe"; fi; \
		out="$(DIST)/$(BIN)_$${goos}_$${goarch}$${ext}"; \
		echo "building $$out"; \
		GOOS=$$goos GOARCH=$$goarch \
			go build -trimpath -ldflags="$(LDFLAGS)" -o "$$out" $(PKG) \
			|| exit $$?; \
	done

clean: ## Remove build artifacts (bin/ and dist/)
	rm -rf $(BIN_DIR) $(DIST)

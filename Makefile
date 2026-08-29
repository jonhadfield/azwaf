PACKAGES := go list ./... | grep -v /examples

# Pin the linter. `go run <pkg>@<version>` ignores whatever golangci-lint
# happens to be on PATH and builds the pinned version with the local Go
# toolchain, so its type-checker always matches the Go being used. An installed
# binary built by an older Go panics with "file requires newer Go version" once
# the local toolchain moves ahead of it.
GOLANGCI_LINT_VERSION := v2.13.0
GOLANGCI_LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

# Formatters are pinned for the same reason: an unpinned gofumpt or goimports
# reformats the tree the moment upstream changes a rule, producing diff noise
# nobody asked for. GOIMPORTS_VERSION is a golang.org/x/tools version.
GOIMPORTS_VERSION := v0.49.0
GOFUMPT_VERSION := v0.11.0
GOIMPORTS := go run golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)
GOFUMPT := go run mvdan.cc/gofumpt@$(GOFUMPT_VERSION)

# `fmt` and `lint` run their tools via `go run`, so no install step is required.
# This target remains for anyone who wants the binaries on PATH as well, and
# installs the same pinned versions.
setup:
	go install -v golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)
	go install -v mvdan.cc/gofumpt@$(GOFUMPT_VERSION)

clean:
	rm -rf ./dist

test:
	go test -v -failfast -timeout=600s -covermode=atomic -coverprofile=coverage.txt $(shell $(PACKAGES))

test.integration:
	go test -v -failfast -timeout=600s -covermode=atomic -coverprofile=coverage.txt $(shell $(PACKAGES))

coverage: test
	go tool cover -html coverage.txt

fmt:
	$(GOIMPORTS) -w . && $(GOFUMPT) -l -w .

tool-versions:
	@$(GOLANGCI_LINT) --version
	@echo "goimports golang.org/x/tools@$(GOIMPORTS_VERSION)"
	@echo "gofumpt   mvdan.cc/gofumpt@$(GOFUMPT_VERSION)"

lint:
	$(GOLANGCI_LINT) run ./...

ci: lint test

# where `make install` puts the binary
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
# sudo only when neither the target directory nor its parent is writable: a
# not-yet-created ~/.local/bin needs no privileges, a root-owned /usr/local/bin does
SUDO := $(shell test -w "$(BINDIR)" 2>/dev/null || test -w "$(dir $(BINDIR))" 2>/dev/null || echo sudo)

BUILD_TAG := $(shell git describe --tags 2>/dev/null)
BUILD_SHA := $(shell git rev-parse --short HEAD)
BUILD_DATE := $(shell date -u '+%Y/%m/%d:%H:%M:%S')

build:
	CGO_ENABLED=0 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf" cmd/azwaf/*.go

build-all:
	GOOS=darwin  CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_darwin_amd64"  cmd/azwaf/*.go
	GOOS=darwin  CGO_ENABLED=0 GOARCH=arm64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_darwin_arm64"  cmd/azwaf/*.go
	GOOS=linux   CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_linux_amd64"   cmd/azwaf/*.go
	GOOS=linux   CGO_ENABLED=0 GOARCH=arm   go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_linux_arm"     cmd/azwaf/*.go
	GOOS=linux   CGO_ENABLED=0 GOARCH=arm64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_linux_arm64"   cmd/azwaf/*.go
	GOOS=netbsd  CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_netbsd_amd64"  cmd/azwaf/*.go
	GOOS=openbsd CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_openbsd_amd64" cmd/azwaf/*.go
	GOOS=freebsd CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_freebsd_amd64" cmd/azwaf/*.go
	GOOS=windows CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_windows_amd64.exe" cmd/azwaf/*.go

build-linux:
	GOOS=linux CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_linux_amd64" cmd/azwaf/*.go

# install builds azwaf and installs it to $(BINDIR), on both macOS and Linux.
# Override the location with: make install PREFIX=~/.local
#
# sudo is used only when $(BINDIR) is not writable by the current user, which is
# the difference between the two platforms in practice: /usr/local/bin is
# usually user-owned on macOS with Homebrew, and root-owned on Linux.
install: build
	$(SUDO) install -d "$(BINDIR)"
	$(SUDO) install -m 0755 .local_dist/azwaf "$(BINDIR)/azwaf"
	@echo "installed $(BINDIR)/azwaf"

uninstall:
	$(SUDO) rm -f "$(BINDIR)/azwaf"
	@echo "removed $(BINDIR)/azwaf"

# kept so anything scripted against the old names keeps working
mac-install: install

linux-install: install

find-updates:
	go list -u -m -json all | go-mod-outdated -update -direct

critic:
	gocritic check -enableAll ./...

gosec:
	gosec -tests ./...

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: install uninstall mac-install linux-install build build-all clean test lint fmt ci

.DEFAULT_GOAL := build

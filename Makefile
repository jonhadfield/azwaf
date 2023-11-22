PACKAGES := go list ./... | grep -v /examples

setup:
	go install -v golang.org/x/tools/cmd/goimports@latest
	go install -v mvdan.cc/gofumpt@latest
	go get -u golang.org/x/tools/cmd/cover

clean:
	rm -rf ./dist

test:
	go test -v -failfast -timeout=600s -covermode=atomic -coverprofile=coverage.txt $(shell $(PACKAGES))

test.integration:
	go test -v -failfast -timeout=600s -covermode=atomic -coverprofile=coverage.txt $(shell $(PACKAGES))

coverage: test
	go tool cover -html coverage.txt

fmt:
	goimports -w . && gofumpt -l -w .

lint:
	golangci-lint run ./...

ci: lint test

BUILD_TAG := $(shell git describe --tags 2>/dev/null)
BUILD_SHA := $(shell git rev-parse --short HEAD)
BUILD_DATE := $(shell date -u '+%Y/%m/%d:%H:%M:%S')

build:
	CGO_ENABLED=0 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf" cmd/azwaf/*.go

build-all:
	GOOS=darwin  CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_darwin_amd64"  cmd/azwaf/*.go
	GOOS=linux   CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_linux_amd64"   cmd/azwaf/*.go
	GOOS=linux   CGO_ENABLED=0 GOARCH=arm   go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_linux_arm"     cmd/azwaf/*.go
	GOOS=linux   CGO_ENABLED=0 GOARCH=arm64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_linux_arm64"   cmd/azwaf/*.go
	GOOS=netbsd  CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_netbsd_amd64"  cmd/azwaf/*.go
	GOOS=openbsd CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_openbsd_amd64" cmd/azwaf/*.go
	GOOS=freebsd CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_freebsd_amd64" cmd/azwaf/*.go
	#GOOS=windows CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_windows_amd64.exe" cmd/azwaf/*.go

build-linux:
	GOOS=linux CGO_ENABLED=0 GOARCH=amd64 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o ".local_dist/azwaf_linux_amd64" cmd/azwaf/*.go

mac-install: build
	install .local_dist/azwaf /usr/local/bin/azwaf

linux-install: build
	sudo install .local_dist/azwaf /usr/local/bin/azwaf

find-updates:
	go list -u -m -json all | go-mod-outdated -update -direct

critic:
	gocritic check -enableAll ./...

gosec:
	gosec -tests ./...

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := build

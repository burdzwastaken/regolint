SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

## all: tidy, fmt, lint, test, build
.PHONY: all
all: tidy fmt lint test test-policies build

## tidy: tidy go modules
.PHONY: tidy
tidy:
	go mod tidy

## fmt: format go and rego source code
.PHONY: fmt
fmt:
	go fmt ./...
	opa fmt -w ./policies

## lint: vet and lint all code
.PHONY: lint
lint:
	go vet ./...
	# can't run it as go tool because it is ahead of their go.mod...?
	golangci-lint run ./... -v

## test: run all Go tests
.PHONY: test
test:
	go test ./...

## test-policies: run OPA policy tests
.PHONY: test-policies
test-policies:
	opa test ./policies -v

## build: build binary
.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o bin/regolint ./cmd/regolint

## plugin: build golangci-lint plugin (Linux/macOS only)
.PHONY: plugin
plugin:
	go build -buildmode=plugin -o bin/regolint.so ./plugin

## clean: remove build artifacts
.PHONY: clean
clean:
	rm -rf bin/

## help: print this help message
.PHONY: help
help:
	@printf 'Usage:\n'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

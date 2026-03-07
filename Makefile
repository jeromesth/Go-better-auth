.PHONY: build test e2e lint fmt vet clean help

## Build all packages
build:
	go build ./...
	cd testutil && go build ./...

## Run all tests (unit + e2e)
test: test-unit e2e

## Run unit tests only
test-unit:
	go test ./...

## Run end-to-end tests
e2e:
	cd e2e && go test ./...

## Run smoke tests only
e2e-smoke:
	cd e2e && go test ./smoke/...

## Run integration tests only
e2e-integration:
	cd e2e && go test ./integration/...

## Run adapter tests only
e2e-adapter:
	cd e2e && go test ./adapter/...

## Run all tests with verbose output
test-verbose:
	go test -v ./...
	cd e2e && go test -v ./...

## Format code
fmt:
	gofmt -w . e2e/

## Run go vet
vet:
	go vet ./...
	cd e2e && go vet ./...

## Run linter (requires golangci-lint)
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed. See https://golangci-lint.run/usage/install/"; exit 1; }
	golangci-lint run ./...

## Tidy all modules
tidy:
	go mod tidy
	cd testutil && go mod tidy
	cd e2e && go mod tidy

## Clean build caches
clean:
	go clean -cache -testcache

## Show help
help:
	@echo "Available targets:"
	@echo "  build            Build all packages"
	@echo "  test             Run all tests (unit + e2e)"
	@echo "  test-unit        Run unit tests only"
	@echo "  e2e              Run all e2e tests"
	@echo "  e2e-smoke        Run smoke tests"
	@echo "  e2e-integration  Run integration tests"
	@echo "  e2e-adapter      Run adapter tests"
	@echo "  test-verbose     Run all tests with verbose output"
	@echo "  fmt              Format code"
	@echo "  vet              Run go vet"
	@echo "  lint             Run golangci-lint"
	@echo "  tidy             Tidy all go.mod files"
	@echo "  clean            Clean build caches"

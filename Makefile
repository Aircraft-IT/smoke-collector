# smoke-collector developer tasks.
GO ?= go
GOLANGCI_LINT ?= golangci-lint
BIN := bin
VERSION ?= 0.1.0-dev
LDFLAGS := -s -w -X gitlab.aircraft.tw/smoke/smoke-collector/internal/version.Version=$(VERSION)

.PHONY: all build build-linux test lint fmt tidy test-identity test-signing test-install test-all release

all: lint test build

build:
	$(GO) build -trimpath -o $(BIN)/ ./cmd/...

## build-linux: static binaries for the release targets
build-linux:
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(BIN)/smoke-collector_linux_$$arch ./cmd/smoke-collector || exit 1; \
	done

test:
	$(GO) test -race -count=1 ./...

lint:
	$(GO) vet ./...
	$(GOLANGCI_LINT) run ./...

fmt:
	gofmt -s -w .

tidy:
	$(GO) mod tidy

## test-identity: --dry-run vs the plan's shell commands, byte for byte (Docker)
test-identity:
	sh scripts/test-identity.sh

## test-signing: minisign -S -l and install.sh's openssl check (minisign, OpenSSL 3)
test-signing:
	sh scripts/test-signing.sh

## test-install: install.sh end to end in containers (Docker, minisign)
test-install:
	sh scripts/test-install.sh

test-all: test test-identity test-signing test-install

## release: VERSION=x.y.z make release (signs with your minisign key; see scripts/release.sh)
release:
	sh scripts/release.sh $(VERSION)

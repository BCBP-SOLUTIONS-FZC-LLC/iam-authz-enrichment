# -----------------------------
# CONFIG
# -----------------------------
-include .env

APP_NAME      ?= iam-authz-enrichment
APP_ENV       ?= dev
GO            ?= go
BUILD_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Private modules — resolved via SSH (git@github.com:) using the global URL rewrite.
# No tokens needed; requires an SSH key registered with github.com/BCBP-SOLUTIONS-FZC-LLC.
export GOPRIVATE  ?= github.com/BCBP-SOLUTIONS-FZC-LLC/*
export GONOSUMDB  ?= github.com/BCBP-SOLUTIONS-FZC-LLC/*

export APP_NAME APP_ENV BUILD_VERSION

TEST_UNIT_PKGS := ./internal/... ./cmd/...
TEST_INT_PKGS  := ./test/integration/...

# Source packages measured for coverage (excludes test helpers and cmd).
COVER_PKG_LIST := $(shell $(GO) list ./internal/... | tr '\n' ',' | sed 's/,$$//')

# -----------------------------
# SETUP
# -----------------------------

.PHONY: setup
setup:
	@test -f .env || cp .env-example .env
	@mkdir -p .git/hooks
	@cp .githooks/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Environment ready (.env); installed .githooks/pre-commit"

.PHONY: help
help:
	@echo "Available commands:"
	@echo "  make setup           - copy .env-example to .env if missing; install .githooks/pre-commit"
	@echo "  make install-hooks   - install local git hooks (.githooks -> .git/hooks)"
	@echo "  make tidy            - go mod tidy"
	@echo "  make fmt             - go fmt ./..."
	@echo "  make vet             - go vet all packages"
	@echo "  make lint            - run golangci-lint"
	@echo "  make arch-lint       - enforce .go-arch-lint.yml component boundaries"
	@echo "  make test            - unit tests (no Docker required)"
	@echo "  make test-ci         - unit tests with race detector + coverage (used in CI)"
	@echo "  make test-integration - Valkey + LocalStack SQS integration tests (requires Docker)"
	@echo "  make race            - unit tests with -race flag"
	@echo "  make run             - run the server locally (go run)"
	@echo "  make build           - compile server binary to bin/"
	@echo "  make cover           - coverage profile + open HTML report"
	@echo "  make cover-func      - coverage summary by function"
	@echo "  make ci              - tidy + fmt-check + vet + lint + arch-lint + test-ci + build"
	@echo "  make docker-up       - start local Valkey + LocalStack"
	@echo "  make docker-down     - stop local containers"
	@echo "  make fmt-check       - verify gofmt formatting (no changes applied)"
	@echo "  make mod-verify      - go mod verify (check module download integrity)"
	@echo "  make vuln-check      - govulncheck on internal packages"
	@echo "  make load-test       - run the test/load harness against a running instance (manual, not part of CI)"
	@echo "  make pin-base-images - fetch SHA digests and pin Dockerfile base images"
	@echo "  make clean           - remove build artefacts"

# -----------------------------
# GIT HOOKS
# -----------------------------

.PHONY: install-hooks
install-hooks:
	@mkdir -p .git/hooks
	@cp .githooks/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Installed git hooks"

# -----------------------------
# GO BASICS
# -----------------------------

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: vet
vet:
	$(GO) vet ./...

# -----------------------------
# LINT
# -----------------------------

.PHONY: lint
lint:
	@echo "Running linter..."
	$(GO) tool golangci-lint run

.PHONY: arch-lint
arch-lint:
	@command -v go-arch-lint >/dev/null || $(GO) install github.com/fe3dback/go-arch-lint@v1.15.0
	go-arch-lint check --project-path .

# -----------------------------
# TESTS
# -----------------------------

.PHONY: test
test:
	$(GO) test $(TEST_UNIT_PKGS) -count=1 -timeout 60s -v

.PHONY: test-ci
test-ci:
	@mkdir -p .coverage
	$(GO) test $(TEST_UNIT_PKGS) -race -count=1 -timeout 120s \
	  -coverpkg=$(COVER_PKG_LIST) -coverprofile=coverage.out

.PHONY: test-integration
test-integration:
	$(GO) test -tags=integration $(TEST_INT_PKGS) -count=1 -timeout 120s -v

.PHONY: race
race:
	$(GO) test $(TEST_UNIT_PKGS) -race -count=1 -timeout 120s

# -----------------------------
# RUN / BUILD
# -----------------------------

.PHONY: run
run:
	@-lsof -ti :$${APP_PORT:-8080} | xargs kill -9 2>/dev/null; true
	bash -c 'set -a && source .env && set +a && BUILD_VERSION=$(BUILD_VERSION) $(GO) run ./cmd/server'

.PHONY: build
build:
	@echo "Building binary..."
	@mkdir -p bin
	$(GO) build -ldflags "-X main.buildVersion=$(BUILD_VERSION)" -o bin/$(APP_NAME) ./cmd/server
	@echo "Verifying library packages compile..."
	$(GO) build ./internal/...

# -----------------------------
# DOCKER (VALKEY + LOCALSTACK)
# -----------------------------

.PHONY: docker-up
docker-up:
	@echo "Starting local Valkey + LocalStack (community)..."
	docker compose up -d valkey localstack

.PHONY: docker-down
docker-down:
	@echo "Stopping local containers..."
	docker compose down

.PHONY: pin-base-images
pin-base-images:
	@echo "Fetching SHA digests for Dockerfile base images..."
	@GO_VER=$$(awk '/^go [0-9]/{print $$2}' go.mod) && \
	 CURRENT_TAG=$$(grep -oE 'golang:[0-9]+\.[0-9]+\.[0-9]+-alpine' Dockerfile | head -1) && \
	 GOLANG_DIGEST=$$(docker buildx imagetools inspect golang:$$GO_VER-alpine --format '{{.Manifest.Digest}}') && \
	 DISTROLESS_DIGEST=$$(docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot --format '{{.Manifest.Digest}}') && \
	 sed -i.bak \
	   -e "s|FROM $$CURRENT_TAG.*|FROM golang:$$GO_VER-alpine@$$GOLANG_DIGEST AS builder|" \
	   -e "s|FROM gcr.io/distroless/static-debian12:nonroot.*|FROM gcr.io/distroless/static-debian12:nonroot@$$DISTROLESS_DIGEST|" \
	   Dockerfile && rm -f Dockerfile.bak && \
	 echo "golang:$$GO_VER-alpine $$GOLANG_DIGEST" > .docker-digests && \
	 echo "gcr.io/distroless/static-debian12:nonroot $$DISTROLESS_DIGEST" >> .docker-digests && \
	 echo "Digests written to .docker-digests — commit both Dockerfile and .docker-digests. Base image tag is derived from go.mod's own 'go' directive ($$GO_VER) so a go.mod bump and this pin can never silently drift apart again."

# -----------------------------
# CI
# -----------------------------

.PHONY: ci
ci: tidy fmt-check vet lint arch-lint test-ci build

# -----------------------------
# COVERAGE
# -----------------------------

.PHONY: cover
cover: test-ci
	$(GO) tool cover -html=coverage.out

.PHONY: cover-func
cover-func: test-ci
	$(GO) tool cover -func=coverage.out

# -----------------------------
# CHECKS (mirror what CI runs; safe to call locally before pushing)
# -----------------------------

.PHONY: fmt-check
fmt-check:
	@unformatted=$$(gofmt -l cmd/ internal/ test/); \
	if [ -n "$$unformatted" ]; then \
		echo "FAIL: unformatted files:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo "gofmt: all files formatted"

.PHONY: mod-verify
mod-verify:
	$(GO) mod verify

.PHONY: vuln-check
vuln-check:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./internal/...

# -----------------------------
# LOAD TEST (manual — not part of CI, see test/load)
# -----------------------------

.PHONY: load-test
load-test:
	@echo "Running load harness against APP_GRPC_ADDR (default localhost:9091)..."
	$(GO) run ./test/load

# -----------------------------
# CLEAN
# -----------------------------

.PHONY: clean
clean:
	rm -rf bin .coverage
	rm -f coverage.out coverage.html

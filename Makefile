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
TEST_E2E_PKGS  := ./test/e2e/...

# Source packages measured for coverage (excludes test helpers and cmd).
COVER_PKG_LIST := $(shell $(GO) list ./internal/... | tr '\n' ',' | sed 's/,$$//')

# Every build tag a test file here declares (integration: test/integration,
# e2e: test/e2e). vet and lint run a second pass with all of them — CI's
# quality gate calls `make vet` / `make lint`, so without it the tagged test
# files were never checked.
ALL_TEST_TAGS := integration,e2e

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
	@echo "  make vet             - go vet (default build + every test build tag)"
	@echo "  make lint            - run golangci-lint (default build + every test build tag)"
	@echo "  make arch-lint       - enforce .go-arch-lint.yml component boundaries"
	@echo "  make observability-lint - enforce all logs/metrics/traces route through platform-gincommon"
	@echo "  make metrics-lint       - enforce Enterprise Platform Observability Standard (iam_authz_enrichment_* prefix)"
	@echo "  make database-lint      - enforce all DB connections/config/ops route through platform-pgcommon"
	@echo "  make events-lint        - enforce all events/outbox/dedup route through platform-events"
	@echo "  make image-pin-lint     - enforce Dockerfile golang tag matches go.mod"
	@echo "  make test            - unit tests (no Docker required)"
	@echo "  make test-ci         - unit tests with race detector + coverage (used in CI)"
	@echo "  make test-integration - Valkey + LocalStack SQS integration tests (requires Docker)"
	@echo "  make test-e2e         - real binary over real gRPC against Valkey + SQS (requires make build + Docker)"
	@echo "  make race            - unit tests with -race flag"
	@echo "  make run             - run the server locally (go run)"
	@echo "  make build           - compile server binary to bin/"
	@echo "  make cover           - coverage profile + open HTML report"
	@echo "  make cover-func      - coverage summary by function"
	@echo "  make ci              - tidy + fmt-check + vet + lint + arch-lint + observability-lint + metrics-lint + database-lint + test-ci + build"
	@echo "  make docker-up       - start local Valkey + floci (SQS)"
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
	$(GO) vet -tags=$(ALL_TEST_TAGS) ./...

# -----------------------------
# LINT
# -----------------------------

.PHONY: lint
lint:
	@echo "Running linter..."
	$(GO) tool golangci-lint run ./...
	$(GO) tool golangci-lint run --build-tags=$(ALL_TEST_TAGS) ./...

.PHONY: arch-lint
arch-lint:
	@command -v go-arch-lint >/dev/null || $(GO) install github.com/fe3dback/go-arch-lint@v1.15.0
	go-arch-lint check --project-path .

# database-lint enforces the platform-pgcommon-only routing invariant:
#   Connections → postgres.OpenPool (→ pgcommon.NewPool)
#   Config      → pgcommon.ConfigFromEnv() / postgres.DSNFromEnv()
#   Operations  → pgcommon helpers (IsConnectionException / IsPgError / ...)
# Also enforces the HLD §5.4 invariant: this service has no schema, so
# cmd/server must never call OpenPool / migrate / outbox runner.
.PHONY: database-lint
database-lint:
	@bash .github/scripts/check-database-routing.sh

# observability-lint enforces the platform-gincommon-only routing invariant:
#   Logs    → logger.NewLogger (Zap, structured, redacted)
#   Metrics → gincommon.MetricsRegisterer() via promauto.With()
#   Traces  → gincommon.InitTracingFromEnv() global TracerProvider
# Any violation of this constraint means observability data bypasses the shared
# sink — breaking redaction, label consistency, and distributed trace continuity.
.PHONY: observability-lint
observability-lint:
	@bash .github/scripts/check-observability-routing.sh

# metrics-lint enforces the Enterprise Platform Observability Standard:
#   All metric names must use the iam_authz_enrichment_ prefix (Tier 3).
#   Counters must end with _total; histograms must end with _seconds.
#   No high-cardinality labels (user_id, tenant_id, etc.) in metric definitions.
.PHONY: metrics-lint
metrics-lint:
	@bash .github/scripts/check-metrics-naming.sh

# events-lint enforces the platform-events-only routing invariant:
#   Consumers  → events.NewSQSConsumerWithClient via buildConsumer
#   Config     → config.LoadSQS / SQSConfigFromEnv / SQSConsumerOptions
#   Glue       → events.GlueDecodeCodec{} via events.WithConsumerCodec
#   Dedup      → Envelope.ID via MarkProcessed SET NX + EvictProcessed on error/panic
#   Outbox     → skipped (consume-only, HLD §5.4 / EVT-2)
#   Metrics    → events.InitMetrics → gincommon.MetricsRegisterer()
.PHONY: events-lint
events-lint:
	@bash .github/scripts/check-events-routing.sh

# image-pin-lint enforces Dockerfile's golang:<ver>-alpine tag (and
# .docker-digests) match go.mod's go directive. The official image sets
# GOTOOLCHAIN=local, so a lagging pin fails at `go mod download`.
.PHONY: image-pin-lint
image-pin-lint:
	@bash .github/scripts/check-golang-image-pin.sh

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

# test-e2e starts the real compiled binary (run `make build` first) against
# a real Valkey + SQS emulator (floci locally via `make docker-up`,
# LocalStack in CI) and a fake Org & Membership/Tender ACL HTTP server,
# driving it over a real gRPC connection — see test/e2e's package doc for
# why this exists alongside the unit and integration tiers above. Requires
# E2E_BINARY_PATH (default ./bin/iam-authz-enrichment, i.e. `make build`'s
# own output) plus VALKEY_URL/AWS_ENDPOINT_URL pointed at real infra.
.PHONY: test-e2e
test-e2e:
	$(GO) test -tags=e2e $(TEST_E2E_PKGS) -count=1 -timeout 120s -v

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
# DOCKER (VALKEY + FLOCI)
# -----------------------------

.PHONY: docker-up
docker-up:
	@echo "Starting local Valkey + floci (SQS)..."
	docker compose up -d valkey floci floci-ui

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
ci: tidy fmt-check vet lint arch-lint observability-lint metrics-lint database-lint events-lint image-pin-lint test-ci build

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

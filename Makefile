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
	@echo "  make test            - unit tests (no Docker required)"
	@echo "  make test-ci         - unit tests with race detector + coverage (used in CI)"
	@echo "  make test-integration - Valkey + LocalStack SQS integration tests (requires Docker)"
	@echo "  make test-e2e         - real binary over real gRPC against Valkey + SQS (requires make build + Docker)"
	@echo "  make race            - unit tests with -race flag"
	@echo "  make run             - run the server locally (go run)"
	@echo "  make build           - compile server binary to bin/"
	@echo "  make cover           - coverage profile + open HTML report"
	@echo "  make cover-func      - coverage summary by function"
	@echo "  make cover-all       - whole-module coverage incl. cmd/server (unit + e2e on an instrumented binary; needs make docker-up)"
	@echo "  make ci              - tidy + fmt-check + vet + lint + arch-lint + metrics-check + test-ci + build"
	@echo "  make metrics-check   - observability standard: naming, governance, metricslint, inventory, PrometheusRule drift, alert tests"
	@echo "  make metrics-inventory - regenerate docs/observability/metric-registry.md"
	@echo "  make prometheusrule  - regenerate the Helm PrometheusRule from deploy/monitoring/app-alerts.yml"
	@echo "  make docker-up       - start local Valkey + floci (SQS)"
	@echo "  make docker-down     - stop local containers"
	@echo "  make fmt-check       - verify gofmt formatting (no changes applied)"
	@echo "  make mod-verify      - go mod verify (check module download integrity)"
	@echo "  make vuln-check      - govulncheck on the whole module (accepted exceptions: .github/govulncheck-allow.txt)"
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

# -----------------------------
# OBSERVABILITY (docs/observability/README.md § CI enforcement)
# -----------------------------
# metrics-check: every Enterprise Platform Observability Standard check —
# collector construction/naming, proposed-metric governance, platform-gincommon's
# metricslint on a real scrape (+ refs + inventory drift), Helm PrometheusRule
# drift, and the promtool alert unit tests.
.PHONY: metrics-check metrics-naming metrics-registry-lint metrics-lint metrics-inventory prometheusrule prometheusrule-check rules-test
metrics-check: metrics-naming metrics-registry-lint metrics-lint prometheusrule-check rules-test

metrics-naming:
	bash .github/scripts/check-metric-naming.sh

metrics-registry-lint:
	bash .github/scripts/metrics-registry-lint.sh

metrics-lint:
	bash .github/scripts/metricslint.sh

# metrics-inventory: regenerate docs/observability/metric-registry.md from the
# pinned registry and a real scrape (metrics-lint fails when it is stale).
metrics-inventory:
	METRICS_INVENTORY_WRITE=1 bash .github/scripts/metricslint.sh

# prometheusrule: regenerate the Helm PrometheusRule from deploy/monitoring/app-alerts.yml.
prometheusrule:
	python3 .github/scripts/render-prometheusrule.py

prometheusrule-check:
	python3 .github/scripts/render-prometheusrule.py --check

# rules-test: promtool check + unit tests for the alert rules. Uses a local
# promtool, else the pinned prom/prometheus image.
PROMETHEUS_IMAGE ?= prom/prometheus:v3.5.0
rules-test:
	@if command -v promtool >/dev/null; then \
	  promtool check rules deploy/monitoring/app-alerts.yml && \
	  promtool test rules deploy/monitoring/tests/app-alerts.test.yml; \
	else \
	  docker run --rm -v "$(CURDIR)/deploy/monitoring:/rules" -w /rules --entrypoint promtool $(PROMETHEUS_IMAGE) check rules app-alerts.yml && \
	  docker run --rm -v "$(CURDIR)/deploy/monitoring:/rules" -w /rules --entrypoint promtool $(PROMETHEUS_IMAGE) test rules tests/app-alerts.test.yml; \
	fi

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
ci: tidy fmt-check vet lint arch-lint metrics-check test-ci build

# -----------------------------
# COVERAGE
# -----------------------------

.PHONY: cover
cover: test-ci
	$(GO) tool cover -html=coverage.out

.PHONY: cover-func
cover-func: test-ci
	$(GO) tool cover -func=coverage.out

# cover-all: whole-module coverage including cmd/server, which test-ci's gate
# leaves out (its run() binds real ports and blocks on signals). Unit tests
# write binary coverage data, the e2e suite runs a coverage-instrumented build
# of the real binary (go build -cover), and the two are merged. Needs the same
# Valkey + SQS emulator as test-e2e (`make docker-up`). Report only, not a gate.
COVER_ALL_DIR ?= .cover-all
MODULE := github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment
.PHONY: cover-all
cover-all:
	rm -rf $(COVER_ALL_DIR) && mkdir -p $(COVER_ALL_DIR)/unit $(COVER_ALL_DIR)/e2e $(COVER_ALL_DIR)/merged
	$(GO) build -cover -coverpkg=$(MODULE)/internal/...,$(MODULE)/cmd/... -o $(COVER_ALL_DIR)/iam-authz-enrichment ./cmd/server
	$(GO) test -cover -coverpkg=$(MODULE)/internal/...,$(MODULE)/cmd/... $(TEST_UNIT_PKGS) -count=1 -args -test.gocoverdir=$(CURDIR)/$(COVER_ALL_DIR)/unit
	GOCOVERDIR=$(CURDIR)/$(COVER_ALL_DIR)/e2e E2E_BINARY_PATH=$(CURDIR)/$(COVER_ALL_DIR)/iam-authz-enrichment \
	  $(GO) test -tags=e2e $(TEST_E2E_PKGS) -count=1 -timeout 300s
	$(GO) tool covdata merge -i=$(COVER_ALL_DIR)/unit,$(COVER_ALL_DIR)/e2e -o=$(COVER_ALL_DIR)/merged
	$(GO) tool covdata textfmt -i=$(COVER_ALL_DIR)/merged -o=$(COVER_ALL_DIR)/coverage.out
	$(GO) tool cover -func=$(COVER_ALL_DIR)/coverage.out | tail -1
	$(GO) tool covdata percent -i=$(COVER_ALL_DIR)/merged

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
	bash .github/scripts/vuln-check.sh

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

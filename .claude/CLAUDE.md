# CLAUDE.md

This file provides guidance to Claude Code when working with the **AuthZ Enrichment Service** (`iam-authz-enrichment`), a Go microservice in the IAM subsystem.

> **Detail files** (read on demand — do not always load):
> - `.claude/architecture.md` — full directory tree, shared-lib details, dependency rules
> - `.claude/key-files.md` — per-file invariants, security notes, judgment calls

## What This Repo Is

`iam-authz-enrichment` is a **private Go service** (module: `github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment`, Go 1.26.9+) that implements Envoy's `ext_authz` v3 gRPC contract (`envoy.service.auth.v3.Authorization/Check`) as the platform's Policy Decision Point. It is the **sole inbound interface** — no business HTTP API, no database, publishes zero events.

**Key responsibilities:**
- Evaluate the §3.1 precedence chain (first-failing-check-wins): subject resolution → read-only gate → base role/department policy → tender-ACL overlay → MFA-freshness gate.
- Cache membership/tenant/tender-ACL context in Valkey with jittered TTLs, serving both the fresh-read and §7 stale-if-error paths from one envelope.
- Consume 5 SQS queues (membership/user/billing/tenant/tender) — 21 event types total — to evict stale cache entries. Idempotent via `ae:processed:{event_id}`, no publishing. Glue-encoded envelopes decoded by `events.GlueDecodeCodec`. `MembershipRevoked` gets wider eviction (also clears `ae:tender_acl` per user — LLD §16 AE-20). `tenant-authz-q` handles 8 types: TenantConverted, TenantRealmReady, TenantSettingChanged (CD-37), TenantSuspended, TenantReactivated (operator), TenantOffboarded, TrialExpired, TrialReactivated.

**Does NOT own:** JWT issuance/validation (Envoy's `jwt_authn` — identity read only from `MetadataContext`, never headers), MFA enrollment, realm/tenant provisioning, durable schema/database, policy-authoring UI, rate limiting, active session revocation, durable delegation data (`iam-delegation`, ADR-0008), tender-ACL persistence (`iam-tender-acl`, ADR-0007 Wave 3 Phase 4 — this service still performs the TAC-4 *check*).

**Source of truth for:** the Allow/Deny decision and its 6 injected headers on every proxied request.

## Common Commands

```bash
make setup           # Copy .env-example → .env; install .githooks/pre-commit (run once)
make tidy            # go mod tidy
make fmt             # go fmt ./...
make fmt-check       # Verify gofmt without modifying (mirrors CI)
make vet             # go vet ./...
make lint            # golangci-lint (via go tool golangci-lint)
make arch-lint       # enforce .go-arch-lint.yml component boundaries
make mod-verify      # go mod verify
make vuln-check      # govulncheck — fails on reachable vulns not in .github/govulncheck-allow.txt
make test            # unit tests (no Docker)
make test-ci         # unit tests with -race + coverage (CI; gated at 100%)
make test-integration # real Valkey + real SQS (build tag `integration`, requires Docker)
make test-e2e        # real binary over real gRPC (build tag `e2e`, requires `make build` + Docker)
make race            # unit tests with -race flag
make run             # run server locally (:8080 HTTP, :9091 gRPC, :9090 metrics)
make build           # compile to bin/iam-authz-enrichment
make cover / cover-func
make metrics-check   # observability standard checks (naming, governance, lint, drift, alert tests)
make metrics-inventory # regenerate docs/observability/metric-registry.md (never edit by hand)
make prometheusrule  # regenerate deploy/helm/templates/prometheusrule.yaml (never edit by hand)
make ci              # tidy + fmt-check + vet + lint + arch-lint + metrics-check + test-ci + build
make docker-up / docker-down  # Valkey + floci (SQS) + floci-ui only
make install-hooks   # re-sync .githooks/pre-commit → .git/hooks
make load-test       # manual 500 RPS harness (not in CI)
make pin-base-images / make clean
```

Single test:
```bash
go test ./internal/usecase/... -run TestChecker_Precedence -v
go test -tags=integration ./test/integration/... -run TestSQS_DLQ -v
go test -tags=e2e ./test/e2e/... -run TestGoldenPath_Allow -v
```

**Coverage:** tests live alongside production code (`internal/.../*_test.go`). `test/` holds only `fixtures/`, `integration/`, `e2e/` (both build-tag gated), and `load/`. `make test-ci` gates at 100% on `internal/...` — `cmd/server` is excluded (startup/shutdown wiring, not practically unit-testable to 100%); `make cover-all` measures it via e2e + `-cover` binary (~97% whole module, ~82% cmd/server), as a report not a gate. Don't add a `test/unit/` tree.

**Tool note:** `golangci-lint` is a `go.mod` tool directive, invoked via `go tool golangci-lint`. `go-arch-lint` is installed on demand by `make arch-lint`.

**Env vars:** every field defaults (`envOr`). Three exceptions — fatal outside `APP_ENV=dev`: (1) `ORG_MEMBERSHIP_BASE_URL`, (2) `TENDER_ACL_BASE_URL`, (3) any `*_AUTHZ_QUEUE_URL` left blank (consumer starts idle, looks healthy, never evicts). Also rejects (any env) two of the five queue URLs set to the same value — corrupts watchdog streak tracking. Use `config.ResolveAppEnv()` — never read `APP_ENV` directly.

## Architecture

Clean Architecture — dependencies point inward: `domain` ← `usecase` ← `adapter` ← `cmd`. Nothing in `internal/domain` or `internal/usecase` imports an adapter package.

See `.claude/architecture.md` for the full directory tree, shared library details, and enforced dependency rules.

## See Also

- **`docs/lld/iam-lld-authz-enrichment.md`** — LLD: precedence chain, cache-key table, event-invalidation table, §7 failure matrix, §9 DenyReason/status table, §10 security invariants, §16 `AE-#` decision register. Document of record when other docs disagree.
- **`README.md`** — mental model, `Authorization.Check` interface contract, Envoy config sketch, local dev, `grpcurl`/`grpcui` walkthroughs.
- **`ARCHITECTURE.md`** — layer model, package-dependency graph, request-flow/cache-strategy/event-flow/failure-handling diagrams, key invariants, STRIDE threat model.
- **`CONTRIBUTING.md`** — branch naming, PR checklist, commit style, step-by-step guides for extending each layer.
- **`VERSIONING.md`** — SemVer rules for the runtime contract (DenyReason/headers/env vars/values.yaml), image tag scheme, maintainer release checklist.
- **`api/asyncapi.yaml`** — 5-queue/15-event-type consumer contract. Served at `GET /asyncapi` and `GET /asyncapi.yaml` (DocsConfig-gated).
- **`.github/SECURITY.md`** — vulnerability reporting scope (identity source, header injection, MFA caching, tenant scoping, fail-closed, log redaction).
- **`docs/observability/`** — Platform Observability Standard: README, metric-registry.md (generated), migration.md, runbooks.md.
- **`docs/runbook.md`** — per-alert triage and common startup failure modes.

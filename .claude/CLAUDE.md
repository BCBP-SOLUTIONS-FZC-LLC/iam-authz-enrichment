# CLAUDE.md

This file provides guidance to Claude Code when working with the **AuthZ Enrichment Service** (`iam-authz-enrichment`), a Go microservice in the IAM subsystem.

> **Detail files** (read on demand — do not always load):
> - `.claude/architecture.md` — full directory tree, shared-lib details, dependency rules
> - `.claude/key-files.md` — per-file invariants, security notes, judgment calls

## What This Repo Is

`iam-authz-enrichment` is a **private Go service** (module: `github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment`, Go 1.26.10+) that implements Envoy's `ext_authz` v3 gRPC contract (`envoy.service.auth.v3.Authorization/Check`) as the platform's Policy Decision Point. It is the **sole inbound interface** — no business HTTP API, no database, publishes zero events.

**Key responsibilities:**
- Evaluate the §3.1 precedence chain (first-failing-check-wins): subject resolution → read-only gate → base role/department policy → tender-ACL overlay → MFA-freshness gate.
- Cache membership/tenant/tender-ACL context in Valkey with jittered TTLs, serving both the fresh-read and §7 stale-if-error paths from one envelope.
- Consume 5 SQS queues (membership/user/billing/tenant/tender) — 22 event types total — to evict stale cache entries. Idempotent via `ae:processed:{event_id}`, no publishing. Glue-encoded envelopes decoded by `events.GlueDecodeCodec`. `MembershipRevoked` gets wider eviction (also clears `ae:tender_acl` per user — LLD §16 AE-20). `tenant-authz-q` handles 8 types: TenantConverted, TenantRealmReady, TenantSettingChanged (CD-37), TenantSuspended, TenantReactivated (operator), TenantOffboarded, TrialExpired, TrialReactivated.

**Does NOT own:** JWT issuance/validation (Envoy's `jwt_authn` — identity read only from `MetadataContext`, never headers), MFA enrollment, realm/tenant provisioning, durable schema/database, policy-authoring UI, rate limiting, active session revocation, durable delegation data (`iam-delegation`, ADR-0008), tender-ACL persistence (`iam-tender-acl`, ADR-0007 Wave 3 Phase 4 — this service still performs the TAC-4 *check*).

**Source of truth for:** the Allow/Deny decision and its 7 injected headers on every proxied request (`x-tenant-id`, `x-user-id`, `x-departments`, `x-tenant-roles`, `x-plan`, `x-feature-flags`, `x-residency-mode`). `x-residency-mode` is always server-computed (`"standard"`|`"strict"`, CD-37 AE-40); `x-feature-flags` includes a server-appended `"read_only"` sentinel for cancelled-grace tenants.

## Common Commands

```bash
make setup           # Copy .env-example → .env; install .githooks/pre-commit + pre-push (run once)
make tidy            # go mod tidy
make fmt             # go fmt ./...
make fmt-check       # Verify gofmt without modifying (mirrors CI)
make vet             # go vet ./...
make lint            # golangci-lint (via go tool golangci-lint)
make arch-lint       # enforce .go-arch-lint.yml component boundaries
make mod-verify      # go mod verify
make vuln-check      # govulncheck — fails on reachable vulns not in .github/govulncheck-allow.txt
make trivy           # build image + Trivy scan like CI (CRITICAL/HIGH/UNKNOWN, fixed only, .trivyignore); run by .githooks/pre-push (SKIP_TRIVY=1 to skip)
make test            # unit tests (no Docker)
make test-ci         # unit tests with -race + coverage (CI; gated at 100%)
make test-integration # real Valkey + real SQS (build tag `integration`, requires Docker)
make test-e2e        # real binary over real gRPC (build tag `e2e`, requires `make build` + Docker)
make race            # unit tests with -race flag
make run             # run server locally (:8080 HTTP, :9091 gRPC, :9090 metrics)
make build           # compile to bin/iam-authz-enrichment
make cover / cover-func
make metrics-check   # observability standard: collector naming, proposed-metric governance, metricslint on a real scrape + refs + inventory drift, Helm PrometheusRule drift, promtool alert tests
make metrics-inventory # regenerate docs/observability/metric-registry.md (never edit it by hand)
make prometheusrule  # regenerate deploy/helm/templates/prometheusrule.yaml from deploy/monitoring/app-alerts.yml (never edit the Helm rule by hand)
make observability-lint # enforce all logs/metrics/traces pass through platform-gincommon only (.github/scripts/check-observability-routing.sh)
make database-lint   # enforce all DB connections/config/ops pass through platform-pgcommon only (.github/scripts/check-database-routing.sh)
make events-lint     # enforce all SQS events/outbox/dedup pass through platform-events only (.github/scripts/check-events-routing.sh)
make image-pin-lint  # Dockerfile golang:<ver>-alpine tag (and .docker-digests) must match go.mod's go directive
make ci              # tidy + fmt-check + vet + lint + arch-lint + observability/database/events/image-pin lints + metrics-check + test-ci + build (mirrors CI)
make docker-up / docker-down   # Valkey + floci (SQS) + floci-ui only — app itself usually runs via `make run`
make install-hooks   # re-sync .githooks/pre-commit + pre-push → .git/hooks
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

**Env vars:** every field defaults (`envOr`). Five exceptions — all in `config.Load()`, fatal outside `APP_ENV=dev`: (1) `ORG_MEMBERSHIP_BASE_URL` / (2) `TENDER_ACL_BASE_URL` left at the dev default, (3) `VALKEY_URL` without `rediss://` (Valkey must be TLS in non-dev), (4) both `SHARED_REALM_ISSUER` and `REALM_TENANT_MAP_SEED` empty (no tenant-resolution path — every request silently `DENY_MALFORMED_IDENTITY`), (5) any `*_AUTHZ_QUEUE_URL` left blank (consumer starts idle, looks healthy, never evicts). Also rejects (any env) two of the five queue URLs set to the same value — corrupts watchdog streak tracking. Use `config.ResolveAppEnv()` — never read `APP_ENV` directly.

**Deny responses (AE-42, LLD §17):** every deny reaches the client as RFC 9457 `application/problem+json`, built with platform-gincommon `pkg/problem` in `grpc/response.go`: `type` = the platform type for the status (`platform/unauthorized` / `platform/forbidden` / `platform/service-unavailable`), `errorCode` = the `DENY_*` reason, a fixed caller-safe `detail`, `instance` = path without query, `traceId`. The gRPC `Status.Message` keeps the bare reason. Never put internal causes in `detail`.

**Non-active members (AE-47, LLD §8.2.1):** I-8 returns a suspended member's row with `200` and `status: "suspended"`. The org-membership client treats any `status` but `active` (missing included) as `ErrNotFound`, so the member is negative-cached and denied `DENY_UNRESOLVABLE_SUBJECT` like a 404; their roles never reach `ae:ctx` or a header.

**Operator path (CD-52, LLD §8.9):** tokens from `OPERATOR_REALM_ISSUER` (the platform realm; empty = off) bypass tenant resolution. They are allowed only on `/api/v1/operator/*` with the `platform_operator` realm role, and get `x-tenant-roles: platform_operator`, `x-user-id` = `sub`, and `x-tenant-id` = the path tenant or the nil UUID. A tenant token can never obtain `platform_operator`. Every operator decision is logged as `operator_access`. `config.Load()` also rejects (any env) an operator issuer equal to a tenant issuer. **Still a Phase 1 go-live gate:** the path is off until the platform realm, the gateway operator provider and `OPERATOR_REALM_ISSUER` are in place — open items OP-G1..OP-G6 in LLD §8.9.1 and the `docs/runbook.md` go-live checklist (AE-46).

## Architecture

Clean Architecture — dependencies point inward: `domain` ← `usecase` ← `adapter` ← `cmd`. Nothing in `internal/domain` or `internal/usecase` imports an adapter package.

See `.claude/architecture.md` for the full directory tree, shared library details, and enforced dependency rules.

## See Also

- **`docs/lld/iam-lld-authz-enrichment.md`** — LLD: precedence chain, cache-key table, event-invalidation table, §7 failure matrix, §9 DenyReason/status table, §10 security invariants, §16 `AE-#` decision register. Document of record when other docs disagree.
- **`README.md`** — mental model, `Authorization.Check` interface contract, Envoy config sketch, local dev, `grpcurl`/`grpcui` walkthroughs.
- **`ARCHITECTURE.md`** — layer model, package-dependency graph, request-flow/cache-strategy/event-flow/failure-handling diagrams, key invariants, STRIDE threat model.
- **`CONTRIBUTING.md`** — branch naming, PR checklist, commit style, step-by-step guides for extending each layer.
- **`VERSIONING.md`** — SemVer rules for the runtime contract (DenyReason/headers/env vars/values.yaml), image tag scheme, maintainer release checklist.
- **`api/asyncapi.yaml`** — 5-queue/22-event-type consumer contract. Served at `GET /asyncapi` and `GET /asyncapi.yaml` (DocsConfig-gated).
- **`.github/SECURITY.md`** — vulnerability reporting scope (identity source, header injection, MFA caching, tenant scoping, fail-closed, log redaction).
- **`docs/observability/`** — Platform Observability Standard: README, metric-registry.md (generated), migration.md, runbooks.md.
- **`docs/runbook.md`** — per-alert triage and common startup failure modes.

# CLAUDE.md

This file provides guidance to Claude Code when working with the **AuthZ Enrichment Service** (`iam-authz-enrichment`), a Go microservice in the IAM subsystem.

## What This Repo Is

`iam-authz-enrichment` is a **private Go service** (module: `github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment`, Go 1.26.9+) that implements Envoy's `ext_authz` v3 gRPC contract (`envoy.service.auth.v3.Authorization/Check`) as the platform's Policy Decision Point. It is the **sole inbound interface** — there is no business HTTP API, no database, and it publishes zero events.

**Key responsibilities:**
- Evaluate the §3.1 precedence chain (first-failing-check-wins): subject resolution → read-only gate → base role/department policy → tender-ACL overlay → MFA-freshness gate.
- Cache membership/tenant/tender-ACL context in Valkey with jittered TTLs, serving both the fresh-read and §7 stale-if-error paths from one envelope.
- Consume 5 SQS queues (membership/user/billing/tenant/tender) to evict stale cache entries — idempotent via `ae:processed:{event_id}`, no publishing, DLQ handled entirely at the SQS redrive-policy level (a `DeadLetterHandler` only logs the 5th delivery). Glue-encoded envelopes are decoded by platform-events/v2's built-in `events.GlueDecodeCodec{}` (strips the 18-byte header; no Glue client needed). `membership-authz-q`'s `MembershipRevoked` (LLD §16 AE-20, Org & Membership's per-user removal cascade signal) gets a wider eviction than its other five event types — also clears every `ae:tender_acl` entry for the user, best-effort, since a whole-membership removal leaves per-grant rows inert instead of firing individual `*Revoked` events.

**Does NOT own:** JWT issuance/validation (Envoy's `jwt_authn` does this — identity is read only from `CheckRequest.Attributes.MetadataContext`, never headers), MFA enrollment, realm/tenant provisioning, any durable schema/database, a policy-authoring UI (policies are compiled-in Go), rate limiting/quota enforcement, active session revocation, durable delegation data (owned by `iam-delegation`, extracted from Org & Membership under ADR-0008 — `active_delegations[]` was dropped from I-8's projection and no longer exists anywhere in this codebase), tender-ACL entries persistence (owned by `iam-tender-acl`, extracted under ADR-0007 Wave 3 Phase 4 — this service still performs the TAC-4 tender-ACL *check*, just against that sibling instead of Org & Membership).

**Source of truth for:** the Allow/Deny decision and its 6 injected headers on every request Envoy proxies. Every service behind this filter is a downstream consumer of this contract — changes to `DenyReason`, header names, or `CheckRequest` field usage ripple everywhere.

## Common Commands

```bash
make setup           # Copy .env-example → .env; install .githooks/pre-commit (run once before anything else)
make tidy            # go mod tidy
make fmt             # go fmt ./...
make fmt-check       # Verify gofmt formatting without modifying files (mirrors CI)
make vet             # go vet ./...
make lint            # golangci-lint (via go tool golangci-lint)
make arch-lint       # enforce .go-arch-lint.yml component boundaries
make mod-verify      # go mod verify
make vuln-check      # govulncheck ./internal/...
make test            # unit tests (no Docker required)
make test-ci         # unit tests with -race + coverage (used in CI; gated at 100% by .github/scripts/coverage-gate.sh)
make test-integration # real Valkey + real SQS integration tests (build tag `integration`, requires Docker — floci locally, LocalStack in CI)
make test-e2e        # real compiled binary over a real gRPC connection (build tag `e2e`, requires `make build` + Docker)
make race            # unit tests with -race flag
make run             # run the server locally (:8080 HTTP, :9091 gRPC, :9090 metrics)
make build           # compile to bin/iam-authz-enrichment
make cover / cover-func
make observability-lint # enforce all logs/metrics/traces pass through platform-gincommon only (.github/scripts/check-observability-routing.sh)
make metrics-lint    # enforce Enterprise Platform Observability Standard: iam_authz_enrichment_* prefix, _total/_seconds suffixes, no high-cardinality labels (.github/scripts/check-metrics-naming.sh)
make database-lint   # enforce all DB connections/config/ops pass through platform-pgcommon only (.github/scripts/check-database-routing.sh)
make events-lint     # enforce all SQS events/outbox/dedup pass through platform-events only (.github/scripts/check-events-routing.sh)
make ci              # tidy + fmt-check + vet + lint + arch-lint + observability-lint + metrics-lint + database-lint + events-lint + test-ci + build (mirrors CI)
make docker-up / docker-down   # Valkey + floci (SQS) + floci-ui only — app itself usually runs via `make run`
make install-hooks   # re-sync .githooks/pre-commit → .git/hooks
make load-test       # manual 500 RPS harness (test/load), not run in CI
make pin-base-images  # fetch SHA digests and pin Dockerfile base images
make clean
```

To run a single test:
```bash
go test ./internal/usecase/... -run TestChecker_Precedence -v
go test -tags=integration ./test/integration/... -run TestSQS_DLQ -v
go test -tags=e2e ./test/e2e/... -run TestGoldenPath_Allow -v
```

**Coverage note:** tests live alongside production code (`internal/.../*_test.go`), not under `test/` — `test/` holds only `fixtures/`, `integration/` and `e2e/` (both build-tag gated), and `load/`. `make test-ci` sets `-coverpkg` to every `internal/...` package (not `cmd/...`, despite `TEST_UNIT_PKGS` running tests there too — `cmd/server`'s `run()` is startup/shutdown wiring that binds real ports and blocks on OS signals, not practically unit-testable to 100% without a larger refactor; this is a deliberate, documented scope choice, not an oversight, surfaced by the same production-readiness audit that produced §16 AE-33/AE-34 in the LLD). Don't add a separate `test/unit/` tree, that's `iam-user-profile`'s convention, not this repo's.

**Tool directive note:** `golangci-lint` is a `tool` entry in `go.mod`, invoked via `go tool golangci-lint`. `go-arch-lint` is installed on demand by `make arch-lint` if missing (not a `go.mod` tool entry, since it's not `go install`-able as a tool directive target the same way).

**No required env vars — with five exceptions (all in `config.Load()`, not scattered across main.go):** `internal/config/config.go` gives every field a default (`envOr`) — the binary starts fine with a genuinely empty environment (`APP_ENV` itself defaults to `"dev"`). This is why `.github/scripts/smoke-tests.sh` checks `/healthz` liveness rather than "exits non-zero on missing config". The five exceptions, all gated on `APP_ENV` being explicitly set to anything other than `"dev"`: (1) `ORG_MEMBERSHIP_BASE_URL` — or, by the identical check, (2) `TENDER_ACL_BASE_URL` — left at their compiled-in dev defaults; (3) `VALKEY_URL` without the `rediss://` scheme — authorization context in Valkey must be TLS-encrypted in transit in non-dev; (4) both `SHARED_REALM_ISSUER` and `REALM_TENANT_MAP_SEED` being empty — both empty means no tenant-resolution path exists and every request gets `DENY_MALFORMED_IDENTITY` silently; and (5) any of the five `*_AUTHZ_QUEUE_URL` vars left blank — a blank URL starts that consumer idle, which looks healthy (`/readyz` ok) while its cache-eviction/restricted/realm facts never apply. The same block also rejects (regardless of `APP_ENV`) any two of those five queue URL vars set to the same URL — undetected, a duplicate would corrupt `cmd/server/receive_watchdog.go`'s per-URL streak tracking (see that file's own entry below).

## Architecture

Clean Architecture — dependencies point inward: `domain` ← `usecase` ← `adapter` ← `cmd`. Nothing in `internal/domain` or `internal/usecase` imports an adapter package.

```
iam-authz-enrichment/
├── api/
│   ├── asyncapi.yaml                  # AsyncAPI 3.0 — 5 consumed channels / 15 event types / 0 published
│   └── embed.go                       # //go:embed asyncapi.yaml — served at GET /asyncapi (HTML viewer) and
│                                       # GET /asyncapi.yaml (raw), gated by DocsConfig (internal/adapter/inbound/
│                                       # http/router.go) — same convention as iam-org-membership/iam-tender-acl
├── cmd/
│   └── server/
│       ├── main.go                    # composition root: wiring, graceful shutdown (gRPC → HTTP+metrics → consumers → cancel → cache.Close); the gRPC/HTTP/metrics server goroutines and startConsumers/runReceiveErrorWatchdog all report a non-graceful exit to one shared fatalErr channel (LLD §16 AE-28) — a dead gRPC server can't run forever behind healthz's httpGet-only liveness/readiness probes. gRPC GracefulStop and the shared HTTP/metrics Shutdown() are each timeout-bounded (grpcGracefulStopTimeout/httpShutdownTimeout, 10s each, LLD §16 AE-33) so a wedged connection can't stall the SQS-consumer drain behind it, and the three phases' worst-case sum fits deploy/helm/values.yaml's terminationGracePeriodSeconds with a 5s margin
│       └── receive_watchdog.go        # runReceiveErrorWatchdog() — detects a consumer whose ReceiveMessage calls fail forever (platform-events retries this internally and never returns an error, so fatalErr alone can't see it); polls sqs_receive_errors_total per queue, pushes to fatalErr after sustained failure
├── internal/
│   ├── domain/                        # entities, value objects, DenyReason enum — no external deps
│   │   ├── decision.go                # DenyReason (7 consts) + .HTTPStatus(), InjectedHeaders names, CacheResult enum, Decision
│   │   ├── context.go                 # MembershipContext, TenantContext, TenderACL + AccessLevel consts + .Satisfies()
│   │   ├── errors.go                  # ErrNotFound, ErrUnavailable sentinels — kept in domain, not an adapter, so usecase never imports an adapter for these
│   │   └── policy/
│   │       ├── types.go               # Action consts, DepartmentLevel consts, RequestFacts + .IsMutation()/.RequiresApproverGate()/.RequiresTenderACL()
│   │       └── policy.go              # Input, EvaluateBase(), ViolatesReadOnly(), MeetsDepartmentLevel() — §3 base policy as pure predicates
│   ├── usecase/                       # orchestration — the layer inbound adapters call into
│   │   ├── ports.go                   # Cache, OrgMembershipClient, BatchTenderACLClient (separate from OrgMembershipClient — TAC-5 only), Recorder(+NoopRecorder), Logger interfaces
│   │   ├── check.go                   # Checker.check() — the full §3.1 precedence chain, OTel spans, resolveContext/resolveTenderACL/checkMFAFreshness
│   │   ├── failure.go                 # DependencyOutcome/DependencyState/DecideDependencyOutcome() — §7 failure matrix as a pure function
│   │   ├── invalidate.go              # Invalidator — one Handle* method per §5 event type
│   │   ├── tenant_resolve.go          # RealmMap, ResolveTenant() — L1 (in-process) + L2 (ae:realm, Valkey) two-layer cache; L1 negative entries TTL'd via AE_REALM_NEG_TTL, never cached on a transient L2 error
│   │   └── restricted_tenders.go      # RestrictedTenderSet — same two-layer (L1 + ae:restricted L2) shape and negative-cache rules as tenant_resolve.go, via AE_RESTRICTED_NEG_TTL
│   ├── config/
│   │   └── config.go                  # Load() — plain os.Getenv + envOr, every field defaults
│   └── adapter/
│       ├── inbound/
│       │   ├── grpc/                  # envoy.service.auth.v3.Authorization/Check — the primary (only) inbound adapter
│       │   │   ├── claims.go          # decodeClaims() — reads ONLY Attributes.MetadataContext, never headers; authTimeField()
│       │   │   ├── requestfacts.go    # decodeRequestFacts() — reads ContextExtensions (5 keys: policy_action, department_id, etc.) + tenderIDFromPath() (tender_id parsed from the raw URL path — see this file's own Key Files entry)
│       │   │   ├── response.go        # okResponse() (headers sorted for determinism), deniedResponse()
│       │   │   └── server.go          # Server.Check()
│       │   ├── http/
│       │   │   ├── router.go          # /healthz, /readyz (process-startup only, NOT dependency health) + DocsConfig-gated AsyncAPI routes registration (registerDocsRoutes/docsAuthMiddleware) — /metrics has its own dedicated listener (cmd/server's metricsServer); wires gincommon.ObservabilityMiddlewares, same as iam-org-membership/iam-user-profile
│       │   │   └── asyncapi.go        # AsyncAPIHandler (HTML viewer) / AsyncAPIYAMLHandler (raw spec) — reads the api package's embedded asyncapi.yaml; ported verbatim from iam-tender-acl's identical renderer
│       │   └── consumer/              # one handler per §5 SQS queue
│       │       ├── consumer.go        # buildConsumer(), idleConsumer (no-op Start/Stop for a blank queue URL in dev); SQSConfigFromEnv / SQSConsumerOptions / WithConsumerCodec(events.GlueDecodeCodec{}) / WithMaxReceiveCount(4)+DeadLetterHandler
│       │       ├── platform.go        # LoadPlatform — LoadSQS / LoadSNS / LoadOutbox + SNSConfigFromEnv / RunnerConfigFromEnv; cmd/server skips NewSNSPublisher / ApplySchema / NewRunner
│       │       ├── dedup.go           # skipDuplicate / ackUnknown — same helpers as iam-org-membership / iam-user-profile; store is Valkey SET NX (no processed_events table)
│       │       ├── idempotency.go     # IdempotencyStore port + processedHandler() — skipDuplicate (SET NX) is itself the duplicate check; EvictProcessed on handler failure so retries aren't swallowed. No IsProcessed method
│       │       └── handlers.go        # 5 New*Consumer builders + per-event-type switch statements → internal/usecase/invalidate.go; unknown types go through ackUnknown
│       └── outbound/
│           ├── valkey/                # Cache port implementation (go-redis/v9)
│           │   ├── keys.go            # ae:ctx / ae:tenant / ae:tender_acl / ae:neg / ae:processed key builders
│           │   └── cache.go           # entry[T]{Value,FetchedAt,SoftTTL} — the single-envelope trick serving fresh-read AND §7 stale-if-error
│           ├── orgmembership/
│           │   └── client.go          # I-8/I-14 HTTP client (Org & Membership) + TAC-4/TAC-5 HTTP client (iam-tender-acl, ADR-0007 Wave 3 Phase 4) — two base URLs/timeouts/http.Clients, one Go package; getJSON() classifies 404 → ErrNotFound; GetTenderACL classifies 400 → ErrNotFound (TAC-GAP-005), 5xx → ErrUnavailable; DTOs guarantee empty-not-nil slices
│           ├── postgres/              # platform-pgcommon DSN/pool config, Zap logger adapter, OTel tracer, OpenPool wrapper. cmd/server loads PoolConfig then skips NewPool (HLD §5.4 — no schema)
│           │   ├── dsn.go             # DSNFromEnv / MigrationDSNFromEnv / SystemDSNFromEnv; ApplyStatementTimeout
│           │   ├── logger_adapter.go  # Zap → pgcommon domain.Logger
│           │   ├── otel_tracer.go     # gincommon TracerProvider → pgcommon.Config.Tracer
│           │   ├── pool.go            # PoolConfig + SystemPoolConfig + OpenPool — OpenPool is the only allowed constructor
│           │   └── wrap.go            # wrapConnErr — SQLSTATE 08/53/57/58 via pgcommon helpers → domain.ErrUnavailable
│           └── metrics/
│               └── recorder.go        # newRecorder(reg prometheus.Registerer) via promauto.With(reg) — New(reg ...prometheus.Registerer) defaults to the default registry but cmd/server passes gincommon.MetricsRegisterer(); the split exists so tests can pass an isolated registry
├── test/
│   ├── fixtures/                      # hand-written fakes (FakeCache, FakeOrgClient, test logger) — no gomock/mockery
│   ├── integration/                   # build tag `integration` — real Valkey + real SQS (floci locally, LocalStack in CI)
│   ├── e2e/                           # build tag `e2e` — starts the real compiled binary, drives it over a real gRPC
│   │                                   # connection against real Valkey/SQS + a fake Org & Membership/Tender ACL HTTP
│   │                                   # server (LLD §14, §16 AE-33/AE-34's audit). Tenant/tender IDs are scoped to a
│   │                                   # per-run UUID (main_test.go's id()) — ae:restricted has no TTL, and this tier
│   │                                   # runs against a real, persistent Valkey, so an unscoped name would leak state
│   │                                   # across separate `go test` invocations
│   └── load/                          # manual 500 RPS harness, not run in CI
├── docs/lld/iam-lld-authz-enrichment.md  # Low-Level Design — §16 AE-# decision register, the source every §3.1/§4.2/etc. reference in this codebase points back to
├── docs/architecture/mermaid/         # 7 .mmd sources — layer-model, package-dependencies, request-flow, cache-strategy, event-flow, failure-handling, observability-stack
├── scripts/
│   ├── init-localstack.sh             # CI only (.github/workflows/validate-test.yml) — creates the 5 inbound queues + their -dlq's against a bare LocalStack service container
│   └── init-floci.sh                  # docker-compose/local dev only — identical 5 queues + DLQs, via floci (an open-source LocalStack-compatible emulator, same image iam-org-membership/iam-delegation use)
├── .githooks/pre-commit               # tidy + fmt-check + lint, installed by `make setup`
├── Dockerfile  docker-compose.yml  Makefile  go.mod  .golangci.yml  .go-arch-lint.yml
├── ARCHITECTURE.md                    # layer model, request-flow/cache/event/failure-handling diagrams, threat model
├── CONTRIBUTING.md                    # branch naming, PR checklist, commit style, how to extend each layer
├── VERSIONING.md                      # SemVer rules for the runtime contract (DenyReason/headers/env vars/values.yaml), image tag scheme, maintainer release checklist
├── CHANGELOG.md
└── README.md                          # mental model, interface contract, local dev, grpcurl/grpcui walkthroughs
```

### Shared library dependencies

```go
require (
    github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon    v1.6.0
    github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2    v2.1.0
    github.com/BCBP-SOLUTIONS-FZC-LLC/platform-pgcommon/v2  v2.0.1
)
```

- `platform-gincommon` — `pkg/logger` (zap + redaction), `pkg/grpccommon` (`ObservabilityUnaryInterceptors`: panic-recovery → request-id → tracing → metrics → logging). **Not** `ProtectedUnaryInterceptors` — Envoy calls this service over mTLS, not as a JWT-bearing client, so there's no bearer auth to require.
- `platform-events/v2` — import path `github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/...`. `pkg/events` SQS consumer loop (`NewSQSConsumerWithClient`, `WithMaxReceiveCount`, `WithConcurrency`, `WithDrainTimeout`, `WithConsumerCodec`, `GlueDecodeCodec{}`), `pkg/config` (`LoadSQS` / `LoadSNS` / `LoadOutbox` / `SNSConfigFromEnv` / `RunnerConfigFromEnv` / `SQSConsumerOptions`), `pkg/outbox` Config mapping. **No publisher or runner**: consume-only (HLD §5.4); `cmd/server` skips `NewSNSPublisher` / `outbox.ApplySchema` / `NewRunner`. Dedup is Envelope.ID via `skipDuplicate` / `ackUnknown`; store is Valkey SET NX (AE-6). **Glue decoding built-in**: `events.GlueDecodeCodec{}` (platform-events/v2 built-in, replaces the former hand-rolled `glue_decoder.go`).
- `platform-pgcommon/v2` — import path `github.com/BCBP-SOLUTIONS-FZC-LLC/platform-pgcommon/v2/pkg/...`. `ConfigFromEnv` / DSN assembly, Zap `domain.Logger` adapter, OTel query tracer, `pgmetrics.InitWithIdentity`, `NewPool` wrapper. **No live pool**: this service has no schema (HLD §5.4); `cmd/server` loads `PoolConfig` then skips `NewPool` / migrate / outbox. A future schema must open exclusively through `postgres.OpenPool`.

**Not a dependency:** `platform-schemagov` (this service publishes no events, so there's nothing to schema-govern).

### Dependency rules (enforced in CI via `go-arch-lint`)

- `domain` imports nothing outside itself; `domain/policy` imports only `domain`. `config` imports nothing internal at all.
- `usecase` imports only `domain` and `domain/policy` — **never** `config` (TTLs/timeouts arrive as plain constructor parameters, not a config import — see `usecase/ports.go`'s own doc comment).
- `adapter/inbound/*` calls into `usecase` (it's the orchestration layer Envoy's gRPC adapter calls into) — this is the one place the dependency direction differs from `iam-user-profile`'s `core/service`-layer naming; there is no separate `port` package here, `usecase/ports.go` plays that role. One exception: the AsyncAPI viewer (`internal/adapter/inbound/http/asyncapi.go`) reads the embedded spec directly from the `api` package (the compiled-in `api/asyncapi.yaml`, §`api/embed.go`) rather than through `usecase` — the one inbound-adapter dependency besides `usecase`/`domain`/`policy` `.go-arch-lint.yml` allows.
- `adapter/outbound/*` implements `usecase`'s port interfaces; nothing in `domain` or `usecase` imports an adapter.

## Key Files to Know

- **`cmd/server/main.go`** — wiring; `gin.SetMode(gin.ReleaseMode)` outside `APP_ENV=dev` (same convention as `iam-org-membership`/`iam-user-profile`) — found missing entirely by actually running the built binary end-to-end rather than by static analysis; without it, every deployment including production ran Gin in permanent debug mode (per-route registration spam on every startup, Gin's own "switch to release mode" warning in the logs forever). gRPC server gets `reflection.Register(grpcServer)` when `cfg.AppEnv != "production"` (lets `grpcurl`/`grpcui` discover `Check` without a local `.proto` copy), plus a native `grpc.health.v1.Health` service tied to the same `MarkReady()` signal as HTTP `/healthz`. Listens in plaintext unless `GRPC_TLS_CERT_FILE`/`GRPC_TLS_KEY_FILE` are set (`loadServerTLS`) — see the file's comment on why "Envoy calls over mTLS" is an unverified deployment assumption, not something this server enforces. `grpc.MaxRecvMsgSize`/`MaxSendMsgSize` are set well below the 4MiB default (defense-in-depth, `CheckRequest`/`CheckResponse` are small). The HTTP server (health/readiness only) and the `/metrics` server are two separate `http.Server`s on two separate ports/listeners. Background workers: 5 SQS consumers via `startConsumers`, each idle (no-op) if its queue URL env var is blank, each built with its own `events.WithConcurrency(n)` (`*_AUTHZ_QUEUE_CONCURRENCY` env vars, default 4 — `platform-events`' own default is 1, fully serial per queue), plus `runReceiveErrorWatchdog` (`receive_watchdog.go`) started alongside them as a safety net for a consumer stuck with no successful `ReceiveMessage` — see that file's own entry below. **`fatalErr` (LLD §16 AE-28)**: a single shared, 1-buffered channel fed by every background-failure source in this process — `startConsumers`' goroutines, `runReceiveErrorWatchdog`, and (since `deploy/helm/values.yaml`'s liveness/readiness probes are `httpGet` against the HTTP server only, with no `grpc:` probe on the gRPC port) now also the gRPC/HTTP/metrics server goroutines' own non-graceful `Serve`/`ListenAndServe` exits via a small `reportFatal` helper — closing a gap where a dead gRPC server (100% of Envoy's traffic) could run forever behind a `/healthz` that never noticed. `main()`'s shutdown `select` treats `<-fatalErr` identically to `<-quit`. Shutdown order: gRPC `GracefulStop` → HTTP+metrics `Shutdown` → consumers `Stop()` **concurrently** (a `sync.WaitGroup`, not a sequential loop — bounds worst-case shutdown to one drain window instead of five) → `cancelBackgroundWork` → `cache.Close()`. **LLD §16 AE-33**: `GracefulStop` and the shared HTTP+metrics `Shutdown()` context are each timeout-bounded now (`grpcGracefulStopTimeout`/`httpShutdownTimeout`, 10s each) rather than unbounded/a flat 30s — a wedged Envoy connection or in-flight `Check()` call used to be able to stall every later shutdown step (including the consumer drain) until `terminationGracePeriodSeconds` (60s) forced a SIGKILL that skipped the drain entirely; the rebalanced worst case (10+10+35=55s) fits with a 5s margin. Don't restore a flat 30s HTTP/metrics timeout or an unbounded `GracefulStop` — that reopens exactly this gap.
- **`internal/usecase/check.go`** — `check()` implements the full §3.1 chain; **judgment call**: MFA-freshness call failure maps to `DenyMFAStale`, not `DenyServiceUnavailable` (documented inline — a sibling outage on this specific check is treated as "can't confirm freshness" rather than "service down"). `resolveContext`'s outcome switch uses `default:` + `//nolint:exhaustive` rather than an explicit `case OutcomeNormal` — `SiblingReachable: false` is hardcoded at that call site, so `OutcomeNormal` can never actually occur there; an explicit per-value case would compile only with a trailing statement Go's compiler can't prove unreachable, which permanently blocks 100% coverage. Don't "fix" this by re-enumerating the case. `resolveContext`'s two Valkey reads (`GetMembershipContext`/`GetTenantContext`) run concurrently (two goroutines + `sync.WaitGroup`), not sequentially — at the 10ms default `VALKEY_READ_TIMEOUT`, two sequential reads could alone approach the 15ms p99 decision budget (§11.1) on a slow-but-not-erroring Valkey. Verified race-clean (`-race -count=5`). **Security invariant — future `auth_time`**: `checkMFAFreshness()` guards `authTime.After(c.now())` before the duration comparison — a future auth_time produces a negative duration that would silently pass the MFA gate without this guard. **Security invariant — empty TenderID**: if `reqFacts.RequiredAccessLevel != ""` but `reqFacts.TenderID == ""` (e.g. trailing-slash path `/tenders/` or route misconfiguration), `check()` returns `DenyMalformedIdentity` immediately rather than silently skipping the tender-ACL overlay.
- **`internal/usecase/failure.go`** — `DecideDependencyOutcome()` is the §7 table as a pure function, deliberately its own package-level function (not scattered in adapter code) so the test suite can exercise every row directly. The tender-ACL overlay's fail-closed rule is independent of this table — checked separately in `check.go`.
- **`internal/adapter/outbound/valkey/cache.go`** — `mfa_freshness_seconds` is **never** written here — hard invariant, has a dedicated regression test. Any change that folds MFA freshness into the `ae:ctx` envelope is a security regression, not a refactor.
- **`internal/usecase/invalidate.go`** — `NewInvalidator(cache, realmMap, restricted, log, recorder ...Recorder)` accepts an optional variadic `Recorder` (defaults to `NoopRecorder{}` when omitted — all existing call sites in tests compile unchanged; `cmd/server` passes the real recorder). `HandleUserDeleted` and `HandleMembershipRevoked` share the same best-effort-tender-ACL-eviction shape: `EvictTenderACLForUser` failure calls `recorder.ObserveEvictionError(eventType)` and logs a warning but never fails the event, since a partial scan degrades to "stale until its 15s TTL expires", not a correctness failure requiring retry. `HandleMembershipRevoked` (LLD §16 AE-20) exists because a whole-membership removal soft-deletes the `tenant_memberships` row and leaves per-grant rows inert rather than firing individual `*Revoked` events — it's the only `membership-authz-q` event type that needs the wider eviction the other five don't.
- **`internal/adapter/inbound/consumer/idempotency.go`** — `processedHandler()` marks-then-handles via `skipDuplicate` (`MarkProcessed`, SET NX — the atomic check *is* the duplicate check, no separate `IsProcessed` step exists or is needed); on handler failure it calls `Cache.EvictProcessed()` to undo the mark, or a failed message would be falsely treated as already-processed on redelivery and silently skipped instead of retried (this was a real bug, caught by `TestSQS_DLQ_MessageMovesAfterMaxReceiveCount` timing out — see `TestDedupingHandler_RetriesAfterHandlerFailure`). `dedup.go`'s `ackUnknown` is the sibling forward-compat path for an unwired event type (log + ack; the wrapper already claimed the ID). **LLD §16 AE-34**: a `defer`/`recover()` around the handler call does the identical `EvictProcessed` cleanup for a **panic**, not just a returned error, then re-panics so `platform-events`' own top-level recovery still runs unchanged — a panic used to bypass the eviction path entirely, which for most queues only cost a stale cache entry until its TTL but for `tender-authz-q` would have permanently disabled the tender-ACL overlay for that tender (`ae:restricted` has no TTL, §8.5.1).
- **`internal/config/config.go`** — every `envInt`-backed field that can silently misbehave on a zero/negative value goes through `envPositiveInt` instead (`GRPC_MAX_CONCURRENT_STREAMS`, both gRPC message-size limits, all five `*_AUTHZ_QUEUE_CONCURRENCY` vars) — a gRPC server accepting zero concurrent streams, a consumer built with negative concurrency, or a message-size cap that admits nothing should crash-loop the pod at startup, not surface as a confusing runtime symptom. `GRPC_MAX_CONCURRENT_STREAMS` additionally gets an explicit `math.MaxUint32` range check. All five fail-fast non-dev checks live here (not in `main.go`) for testability: (1) `ORG_MEMBERSHIP_BASE_URL`/`TENDER_ACL_BASE_URL` dev-defaults, (2) `VALKEY_URL` must use `rediss://` scheme (TLS) in non-dev — the check is applied unconditionally once `APP_ENV != "dev"` (the `url != ""` guard was removed as dead code since `envOr` always returns a non-empty default); `AE_PROCESSED_EVENT_TTL` defaults to 192h (PE-1 — strictly > 7-day SQS lifetime), (3) both `SHARED_REALM_ISSUER` and `REALM_TENANT_MAP_SEED` empty, (4) blank queue URLs, (5) duplicate queue URLs. `AE_STALE_IF_ERROR_MAX_AGE` is hard-capped at 5m regardless of configured value (§7). Do not move any of these checks back into `main.go` — they need to be unit-testable via `config_test.go`.
- **`cmd/server/receive_watchdog.go`** — verified against the vendored `platform-events` source that its SQS consumer's `Start()` never returns an error for a persistently failing `ReceiveMessage` loop (revoked IAM permissions, a deleted queue) — it retries forever internally, so the existing `fatalErr` restart channel never fires for that failure mode on its own. This file closes the gap by polling `sqs_receive_errors_total` per queue and pushing to `fatalErr` after `staleAfter` (6) consecutive polls with no successful receive. `poll()` deduplicates by queue URL before updating streak state — two friendly queue names racing to update/reset the same URL's counter within one poll would otherwise make that URL's stuck consumer permanently undetectable; `config.go`'s duplicate-queue-URL fail-fast check (above) is the other half of that same defense.
- **`internal/adapter/inbound/grpc/claims.go`** — `decodeClaims()` reads only `req.Attributes.MetadataContext[cfg.Namespace].Fields[cfg.PayloadKey]` — never `req.Attributes.Request.Http.Headers`. A code path that falls back to headers is an identity-spoofing vulnerability, not a convenience fix.
- **`internal/adapter/inbound/grpc/requestfacts.go`** — `tenderIDFromPath()` parses `tender_id` out of `req.Attributes.Request.Http.Path`'s `/tenders/{id}` segment; it is deliberately **not** one of the `ContextExtensions` keys (§16 AE-22 in the LLD). `ExtAuthzPerRoute.check_settings.context_extensions` is a static `map<string,string>` an Envoy route author writes once per route at config time — it has no per-request templating, so it cannot carry a genuine per-resource ID the way it can a route-invariant fact like `policy_action`. Every tender-scoped route (GET/POST/PUT/PATCH/DELETE alike) must keep the tender ID in the URL path — a body-only ID silently disables the tender-ACL overlay for that route instead of erroring.
- **`internal/adapter/inbound/http/router.go`** / **`asyncapi.go`** — the AsyncAPI HTML viewer (`GET /asyncapi`) and raw-spec endpoint (`GET /asyncapi.yaml`), gated by `DocsConfig` (`Environment`/`Enabled`/`AuthToken`): always mounted outside `APP_ENV=production`, opt-in via `DOCS_ENABLED` in production, optionally bearer-token-gated via `DOCS_AUTH_TOKEN`. Ported verbatim from `iam-tender-acl`'s identical renderer — entirely YAML-driven off the embedded `api/asyncapi.yaml`, no service-specific logic. No Swagger half, since this service has no business HTTP API to document one for. `asyncapi.go`'s description/summary truncation **must** go through `truncateRunes` (rune-boundary-safe), never a bare `s[:N]` slice — this was a real bug: `api/asyncapi.yaml`'s `info.description` uses multi-byte box-drawing characters (`─`, U+2500) to draw its producer table, a byte-level `s[:800]` cut landed mid-character, and the `/asyncapi` page rendered `�` (U+FFFD) instead of the description. Caught by `TestAsyncAPIHandler_RealSpec_NeverEmitsReplacementCharacter`, which renders the real embedded spec and asserts no `�` appears anywhere in the output.
- **`internal/adapter/outbound/metrics/recorder.go`** — `New(reg ...prometheus.Registerer)` defaults to `prometheus.DefaultRegisterer` when called with no args, but `cmd/server` passes `gincommon.MetricsRegisterer()` so the `iam_authz_enrichment_*` business counters are explicitly confirmed to land on the same registry as `platform-gincommon`'s own metrics (same convention as `iam-user-profile`). Tests call `newRecorder(reg)` directly with an isolated `prometheus.NewRegistry()` so parallel tests don't collide on the default registry. **New counters (added for production observability)**: `iam_authz_enrichment_tac4_errors_total` (incremented by `ObserveTACDependencyError()` in `check.go`'s `resolveTenderACL` error path — distinguishes a real iam-tender-acl outage from legitimate policy denials in Prometheus); `iam_authz_enrichment_eviction_errors_total{event}` (incremented by `ObserveEvictionError(event)` in `invalidate.go`'s best-effort SCAN failure path). The `Recorder` interface in `ports.go` gained corresponding `ObserveTACDependencyError()` and `ObserveEvictionError(event string)` methods — `NoopRecorder` implements both as no-ops. `BatchTenderACLClient` is a separate interface from `OrgMembershipClient` — it holds only `GetBatchTenderACL` so test fakes for the §3.1 Check() chain don't need to implement a method no Check() path calls. `domain.TenderACL.AccessLevel` is `*string` (not `string`) — absent JSON field decodes as nil, not empty string (TAC-GAP-001).
- **`test/fixtures/cache.go`** — `FakeCache` has a `*Err` field per operation (`SetCtxErr`, `GetTenderACLErr`, `EvictProcessedErr`, …) for error-injection tests; it does not use gomock/mockery, matching `iam-user-profile`'s convention.
- **`test/e2e/main_test.go`** — `TestMain` builds the fake Org & Membership/Tender ACL server, starts the real compiled binary (`E2E_BINARY_PATH`, default `../../bin/iam-authz-enrichment` — `make build` first) as a subprocess with SIGTERM-then-Kill teardown (exercising the real §16 AE-33 graceful-shutdown path), and dials it over a real gRPC connection before running any test. **`runID`/`id()`**: every tenant/tender name a test constructs must go through `id()`, which suffixes a per-process UUID — this suite runs against a real, persistent Valkey (not reset between invocations), and `ae:restricted` has no TTL by design (§8.5.1), so an unscoped name lets one run's residual restriction state corrupt a later run's "not yet restricted" assertion. This bit a first draft of `TestTenderACLOverlay_FullFlow` before the fix. Also: `fakeorg.go`'s `tenderACLFixture.ExpiresAt` must stay `time.Time`, never `string` — the real client decodes TAC-4's response directly into `domain.TenderACL{ExpiresAt time.Time}`, and an empty-string JSON value fails that unmarshal, which is indistinguishable from every other `GetTenderACL` error and fails closed to `DENY_TENDER_ACL_INSUFFICIENT` — a mock bug that looks exactly like a real denial (caught by this suite itself before landing). **Never name a file in this package `mockorg*`** (or add one elsewhere in the repo) — `.gitignore`'s `mockorg*` rule (for README's own throwaway local `mockorg/` walkthrough directory) glob-matches that basename anywhere in the tree, not just at the repo root. A file named `mockorg.go` here was silently excluded from every `git add`, built and passed locally (`go test` reads the working directory regardless of git tracking state), and only broke in CI's fresh checkout with `undefined: mockOrg` — fixed by renaming to `fakeorg.go`/`fakeOrg`, which also matches this codebase's existing test-double naming (`test/fixtures`' `FakeCache`) better than "mock" did anyway.

## See Also

Deep-dive docs live in the repo root (this service doesn't split them into `.claude/*.md` topic files — there's no Postgres/Swagger depth to justify it):

- **`docs/lld/iam-lld-authz-enrichment.md`** — the Low-Level Design: precedence chain, cache-key table, event-invalidation table, §7 failure matrix, §9 DenyReason/status table, §10 security invariants, and the §16 `AE-#` open-questions/decision register (e.g. AE-19 TAC-4 wire-contract confirmation, AE-20 `MembershipRevoked`, AE-22 `tender_id`-from-path). Most other docs in this repo (README, ARCHITECTURE, this file) summarize or restate parts of it; this is the document of record when they disagree.
- **`README.md`** — mental model, `Authorization.Check` interface contract, Envoy config sketch, local dev setup, `grpcurl`/`grpcui` walkthroughs (happy path, tender-ACL overlay, MFA-freshness gate), testing events locally.
- **`ARCHITECTURE.md`** — layer model, package-dependency graph, request-flow/cache-strategy/event-flow/failure-handling diagrams (each backed by a `docs/architecture/mermaid/*.mmd` source), key invariants table, STRIDE threat model.
- **`CONTRIBUTING.md`** — branch naming, PR checklist, commit style, step-by-step guides for adding a precedence step / cached value / event consumer / env var, deployment/CI description.
- **`VERSIONING.md`** — SemVer rules scoped to this service's actual public surface (it's a deployed container + Helm chart, not a `go get`-able library): the `DenyReason`/injected-header/`CheckRequest`-field/env-var/`values.yaml` contract that counts as breaking, the release image's tag scheme, and the maintainer release checklist (CHANGELOG entry → `Chart.yaml` bump → tag → `release.yml`).
- **`api/asyncapi.yaml`** — the 5-queue/15-event-type consumer contract, verified field-for-field against the producing services' own asyncapi.yaml where one was available (Org & Membership, User Profile) and flagged `producer-lifecycle-status: unknown` where it wasn't (Billing Service, Realm Provisioner, Tender Service — no spec present in this workspace). Served live at `GET /asyncapi` (HTML viewer) and `GET /asyncapi.yaml` (raw spec) — `DocsConfig`-gated, same convention as `iam-org-membership`/`iam-tender-acl`.
- **`.github/SECURITY.md`** — vulnerability reporting, scope (identity source, header injection, `mfa_freshness_seconds` caching, tenant scoping, fail-closed vs. bypass, log redaction).
- **`docs/runbook.md`** — what to do when each Prometheus alert / CloudWatch DLQ alarm fires, and the common startup/log-noise failure modes.

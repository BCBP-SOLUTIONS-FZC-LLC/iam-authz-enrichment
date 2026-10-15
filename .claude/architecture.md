# Architecture

## Directory Structure

```
iam-authz-enrichment/
├── api/
│   ├── asyncapi.yaml                  # AsyncAPI 3.0 — 5 consumed channels / 15 event types / 0 published
│   └── embed.go                       # //go:embed asyncapi.yaml — served at GET /asyncapi (HTML viewer) and
│                                       # GET /asyncapi.yaml (raw), gated by DocsConfig (internal/adapter/inbound/
│                                       # http/router.go) — same convention as iam-org-membership/iam-tender-acl
├── cmd/
│   └── server/
│       ├── main.go                    # composition root: wiring, graceful shutdown (gRPC → HTTP+metrics → consumers → cancel → eventCache.Close → cache.Close)
│       ├── factstore.go               # factStore — the store RealmMap/RestrictedTenderSet bind to: GetRealm/GetRestricted on the request-path cache (10ms), SetRealm/SetRestricted on eventCache (VALKEY_EVENT_TIMEOUT, 500ms)
│       └── receive_watchdog.go        # runReceiveErrorWatchdog() — detects a consumer whose ReceiveMessage calls fail forever; wraps each consumer's SQS client to count errors/successes, pushes to fatalErr after sustained failure
├── internal/
│   ├── domain/                        # entities, value objects, DenyReason enum — no external deps
│   │   ├── decision.go                # DenyReason (7 consts) + .HTTPStatus(), InjectedHeaders names, CacheResult enum, Decision
│   │   ├── context.go                 # MembershipContext, TenantContext, TenderACL + AccessLevel consts + .Satisfies()
│   │   ├── errors.go                  # ErrNotFound, ErrUnavailable sentinels
│   │   └── policy/
│   │       ├── types.go               # Action consts, DepartmentLevel consts, RequestFacts + .IsMutation()/.RequiresApproverGate()/.RequiresTenderACL()
│   │       └── policy.go              # Input, EvaluateBase(), ViolatesReadOnly(), MeetsDepartmentLevel() — §3 base policy as pure predicates
│   ├── usecase/                       # orchestration — the layer inbound adapters call into
│   │   ├── ports.go                   # Cache, OrgMembershipClient, BatchTenderACLClient (TAC-5 only), Recorder(+NoopRecorder), Logger interfaces
│   │   ├── check.go                   # Checker.check() — the full §3.1 precedence chain, OTel spans, resolveContext/resolveTenderACL/checkMFAFreshness
│   │   ├── failure.go                 # DependencyOutcome/DependencyState/DecideDependencyOutcome() — §7 failure matrix as a pure function
│   │   ├── invalidate.go              # Invalidator — one Handle* method per §5 event type
│   │   ├── tenant_resolve.go          # RealmMap, ResolveTenant() — L1 (in-process) + L2 (ae:realm, Valkey) two-layer cache
│   │   └── restricted_tenders.go      # RestrictedTenderSet — same two-layer shape as tenant_resolve.go
│   ├── config/
│   │   └── config.go                  # Load() — plain os.Getenv + envOr, every field defaults
│   └── adapter/
│       ├── inbound/
│       │   ├── grpc/                  # envoy.service.auth.v3.Authorization/Check — the primary (only) inbound adapter
│       │   │   ├── claims.go          # decodeClaims() — reads ONLY Attributes.MetadataContext, never headers
│       │   │   ├── requestfacts.go    # decodeRequestFacts() — reads ContextExtensions + tenderIDFromPath()
│       │   │   ├── response.go        # okResponse() (headers sorted for determinism), deniedResponse()
│       │   │   └── server.go          # Server.Check()
│       │   ├── http/
│       │   │   ├── router.go          # /healthz, /readyz, DocsConfig-gated AsyncAPI routes
│       │   │   └── asyncapi.go        # AsyncAPIHandler (HTML viewer) / AsyncAPIYAMLHandler (raw spec)
│       │   └── consumer/              # one handler per §5 SQS queue
│       │       ├── consumer.go        # buildConsumer(), idleConsumer; SQSConfigFromEnv / WithConsumerCodec(events.GlueDecodeCodec) / WithDLQForwarding
│       │       ├── platform.go        # LoadPlatform — LoadSQS / LoadSNS / LoadOutbox
│       │       ├── dedup.go           # skipDuplicate / ackUnknown — Valkey SET NX (no processed_events table)
│       │       ├── idempotency.go     # IdempotencyStore port + processedHandler() — EvictProcessed on handler failure
│       │       └── handlers.go        # 5 New*Consumer builders + per-event-type switch statements → internal/usecase/invalidate.go
│       └── outbound/
│           ├── valkey/                # Cache port implementation (go-redis/v9)
│           │   ├── keys.go            # ae:ctx / ae:tenant / ae:tender_acl / ae:neg / ae:processed key builders
│           │   └── cache.go           # entry[T]{Value,FetchedAt,SoftTTL} — single-envelope trick for fresh-read AND §7 stale-if-error
│           ├── orgmembership/
│           │   └── client.go          # I-8/I-14 HTTP client (Org & Membership) + TAC-4/I-12 HTTP client (iam-tender-acl); getJSON() classifies 404 → domain.ErrNotFound; GetTenderACL also classifies 400 → ErrNotFound (TAC-GAP-005), 5xx → ErrUnavailable; GetBatchTenderACL is TAC-5
│           ├── postgres/              # platform-pgcommon DSN/pool config — cmd/server loads PoolConfig then skips NewPool (no schema)
│           │   ├── dsn.go             # DSNFromEnv / MigrationDSNFromEnv / SystemDSNFromEnv
│           │   ├── logger_adapter.go  # Zap → pgcommon domain.Logger
│           │   ├── pool.go            # PoolConfig + SystemPoolConfig + OpenPool
│           │   └── wrap.go            # wrapConnErr — SQLSTATE 08/53/57/58 → domain.ErrUnavailable
│           └── metrics/
│               └── recorder.go        # New(reg gincommon.Registerer) (*Recorder, error) — validated via gincommon Tier 3 constructors
├── test/
│   ├── fixtures/                      # hand-written fakes (FakeCache, FakeOrgClient, test logger) — no gomock/mockery
│   ├── integration/                   # build tag `integration` — real Valkey + real SQS
│   ├── e2e/                           # build tag `e2e` — real compiled binary over real gRPC connection
│   └── load/                          # manual 500 RPS harness, not run in CI
├── docs/lld/iam-lld-authz-enrichment.md
├── docs/observability/                # README, metric-registry.md (GENERATED), migration.md, runbooks.md
├── deploy/
│   ├── helm/                          # chart — templates/prometheusrule.yaml GENERATED from monitoring/app-alerts.yml
│   ├── iam/                           # reference IRSA policy
│   └── monitoring/                    # app-alerts.yml + tests/app-alerts.test.yml, dlq-alarms.tf.example
├── .github/
│   ├── scripts/                       # coverage-gate, vuln-check, metric scripts, metrics-inventory.py, render-prometheusrule.py
│   └── workflows/                     # validate-quality, validate-test, release
├── docs/architecture/mermaid/         # 7 .mmd sources — layer-model, package-dependencies, request-flow, cache-strategy, event-flow, failure-handling, observability-stack
├── scripts/
│   ├── init-localstack.sh             # CI only — creates 5 queues + DLQs against LocalStack
│   └── init-floci.sh                  # docker-compose/local dev — identical queues via floci
├── .githooks/pre-commit               # tidy + fmt-check + lint, installed by `make setup`
├── Dockerfile  docker-compose.yml  Makefile  go.mod  .golangci.yml  .go-arch-lint.yml
├── ARCHITECTURE.md  CONTRIBUTING.md  VERSIONING.md  CHANGELOG.md  README.md
```

## Shared Library Dependencies

```go
require (
    github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon v1.6.0
    github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2    v2.1.0
    github.com/BCBP-SOLUTIONS-FZC-LLC/platform-pgcommon/v2  v2.0.1
)
```

- **`platform-gincommon`** — `pkg/logger` (zap + redaction), `pkg/grpccommon` (`ObservabilityUnaryInterceptors`: panic-recovery → request-id → tracing → metrics → logging). Uses `ObservabilityUnaryInterceptors`, **not** `ProtectedUnaryInterceptors` — Envoy calls over mTLS, no JWT bearer auth to require. `grpccommon.RegisterKnownMethods` bounds the `grpc_method` label. `pkg/gincommon` is the **only** OTel/Prometheus entry point: `InitTracingWithConfig`, `MetricsHandler`, `NewCounterVec`/`NewCounter`/`NewHistogramVec`, `NewTracer`, `NewSpanTracer`, `InjectTraceContext`. Don't reintroduce local copies (hand-rolled tracer, `promauto`, `promhttp`, local Glue decoder). One direct OTel import remains: `otelhttp` on the outbound transport.

- **`platform-events/v2`** — import path `github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/...`. `pkg/events` SQS consumer loop (`NewSQSConsumer`, `WithMaxReceiveCount`, `WithConcurrency`, `WithDrainTimeout`, `WithConsumerCodec`), `pkg/config` (`LoadSQS`/`LoadSNS`/`LoadOutbox`/`SNSConfigFromEnv`/`RunnerConfigFromEnv`/`SQSConsumerOptions`). **No publisher or runner** — consume-only (HLD §5.4). Dedup via `skipDuplicate`/`ackUnknown`; store is Valkey SET NX (AE-6).

- **`platform-pgcommon/v2`** — import path `github.com/BCBP-SOLUTIONS-FZC-LLC/platform-pgcommon/v2/pkg/...`. DSN assembly, Zap logger adapter, query tracer via `gincommon.NewSpanTracer`, `pgmetrics.InitWithIdentity`, `NewPool` wrapper. **No live pool** — no schema (HLD §5.4). A future schema must use `postgres.OpenPool`.

- **Not a dependency:** `platform-schemagov` — this service publishes no events.

## Dependency Rules (enforced via `go-arch-lint` in CI)

- `domain` imports nothing outside itself; `domain/policy` imports only `domain`. `config` imports nothing internal.
- `usecase` imports only `domain` and `domain/policy` — **never** `config` (TTLs/timeouts arrive as plain constructor parameters).
- `adapter/inbound/*` calls into `usecase`. Exception: `internal/adapter/inbound/http/asyncapi.go` reads the embedded spec from the `api` package directly (allowed in `.go-arch-lint.yml`).
- `adapter/outbound/*` implements `usecase`'s port interfaces; nothing in `domain` or `usecase` imports an adapter.

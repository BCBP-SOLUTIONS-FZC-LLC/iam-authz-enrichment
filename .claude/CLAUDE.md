# CLAUDE.md

This file provides guidance to Claude Code when working with the **AuthZ Enrichment Service** (`iam-authz-enrichment`), a Go microservice in the IAM subsystem.

## What This Repo Is

`iam-authz-enrichment` is a **private Go service** (module: `github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment`, Go 1.26.6+) that implements Envoy's `ext_authz` v3 gRPC contract (`envoy.service.auth.v3.Authorization/Check`) as the platform's Policy Decision Point. It is the **sole inbound interface** — there is no business HTTP API, no database, and it publishes zero events.

**Key responsibilities:**
- Evaluate the §3.1 precedence chain (first-failing-check-wins): subject resolution → read-only gate → base role/department policy → tender-ACL overlay → MFA-freshness gate.
- Cache membership/tenant/tender-ACL context in Valkey with jittered TTLs, serving both the fresh-read and §7 stale-if-error paths from one envelope.
- Consume 5 SQS queues (membership/user/billing/tenant/tender) to evict stale cache entries — idempotent via `ae:processed:{event_id}`, no publishing, DLQ handled entirely at the SQS redrive-policy level. `membership-authz-q`'s `MembershipRevoked` (LLD §16 AE-20, Org & Membership's per-user removal cascade signal) gets a wider eviction than its other five event types — also clears every `ae:tender_acl` entry for the user, best-effort, since a whole-membership removal leaves per-grant rows inert instead of firing individual `*Revoked` events.

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
make test-integration # real Valkey + LocalStack SQS integration tests (build tag `integration`, requires Docker)
make race            # unit tests with -race flag
make run             # run the server locally (:8080 HTTP, :9091 gRPC, :9090 metrics)
make build           # compile to bin/iam-authz-enrichment
make cover / cover-func
make ci              # tidy + fmt-check + vet + lint + arch-lint + test-ci + build (mirrors CI)
make docker-up / docker-down   # Valkey + LocalStack (SQS) only — app itself usually runs via `make run`
make install-hooks   # re-sync .githooks/pre-commit → .git/hooks
make load-test       # manual 500 RPS harness (test/load), not run in CI
make pin-base-images  # fetch SHA digests and pin Dockerfile base images
make clean
```

To run a single test:
```bash
go test ./internal/usecase/... -run TestChecker_Precedence -v
go test -tags=integration ./test/integration/... -run TestSQS_DLQ -v
```

**Coverage note:** tests live alongside production code (`internal/.../*_test.go`), not under `test/` — `test/` holds only `fixtures/`, `integration/` (build-tag gated), and `load/`. `make test-ci` already sets `-coverpkg` to every `internal/...` package; don't add a separate `test/unit/` tree, that's `iam-user-profile`'s convention, not this repo's.

**Tool directive note:** `golangci-lint` is a `tool` entry in `go.mod`, invoked via `go tool golangci-lint`. `go-arch-lint` is installed on demand by `make arch-lint` if missing (not a `go.mod` tool entry, since it's not `go install`-able as a tool directive target the same way).

**No required env vars — with three exceptions:** `internal/config/config.go` gives every field a default (`envOr`) — the binary starts fine with a genuinely empty environment (`APP_ENV` itself defaults to `"dev"`). This is why `.github/scripts/smoke-tests.sh` checks `/healthz` liveness rather than "exits non-zero on missing config" (which is `iam-user-profile`'s pattern, not applicable here). The three exceptions, all gated on `APP_ENV` being explicitly set to anything other than `"dev"`: (1) `ORG_MEMBERSHIP_BASE_URL` — or, by the identical check added for the ADR-0007 Wave 3 Phase 4 TAC-4 split, (2) `TENDER_ACL_BASE_URL` — still being its compiled-in dev default, added because that combination used to start clean and then silently fail every non-cache-hit request forever; and (3) any of the five `*_AUTHZ_QUEUE_URL` vars (`MEMBERSHIP_`/`USER_`/`BILLING_`/`TENANT_`/`TENDER_AUTHZ_QUEUE_URL`) left blank — a blank URL starts that consumer idle, which looks healthy (`/readyz` ok) while its cache-eviction/restricted/realm facts never apply. The same block also rejects (regardless of `APP_ENV`) any two of those five vars set to the same URL — undetected, a duplicate would also corrupt `cmd/server/receive_watchdog.go`'s per-URL streak tracking (see that file's own entry below).

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
│       ├── main.go                    # composition root: wiring, graceful shutdown (gRPC → HTTP → consumers → cancel → cache.Close); the gRPC/HTTP/metrics server goroutines and startConsumers/runReceiveErrorWatchdog all report a non-graceful exit to one shared fatalErr channel (LLD §16 AE-28) — a dead gRPC server can't run forever behind healthz's httpGet-only liveness/readiness probes
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
│   │   ├── ports.go                   # Cache, OrgMembershipClient, Recorder(+NoopRecorder), Logger interfaces
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
│       │       ├── consumer.go        # buildConsumer(), idleConsumer (no-op Start/Stop for a blank queue URL in dev)
│       │       ├── idempotency.go     # IdempotencyStore port + processedHandler() — MarkProcessed (SET NX) is itself the duplicate check; EvictProcessed on handler failure so retries aren't swallowed. No IsProcessed method — removed as dead code, nothing ever called it since MarkProcessed's atomicity already subsumes it
│       │       └── handlers.go        # 5 New*Consumer builders + per-event-type switch statements → internal/usecase/invalidate.go
│       └── outbound/
│           ├── valkey/                # Cache port implementation (go-redis/v9)
│           │   ├── keys.go            # ae:ctx / ae:tenant / ae:tender_acl / ae:neg / ae:processed key builders
│           │   └── cache.go           # entry[T]{Value,FetchedAt,SoftTTL} — the single-envelope trick serving fresh-read AND §7 stale-if-error
│           ├── orgmembership/
│           │   └── client.go          # I-8/I-14 HTTP client (Org & Membership) + TAC-4/I-12 HTTP client (iam-tender-acl, ADR-0007 Wave 3 Phase 4) — two base URLs/timeouts/http.Clients, one Go package; getJSON()/getJSONWith() classify 404 → domain.ErrNotFound; DTOs guarantee empty-not-nil slices
│           └── metrics/
│               └── recorder.go        # newRecorder(reg prometheus.Registerer) via promauto.With(reg) — New(reg ...prometheus.Registerer) defaults to the default registry but cmd/server passes gincommon.MetricsRegisterer(); the split exists so tests can pass an isolated registry
├── test/
│   ├── fixtures/                      # hand-written fakes (FakeCache, FakeOrgClient, test logger) — no gomock/mockery
│   ├── integration/                   # build tag `integration` — real Valkey + real LocalStack SQS
│   └── load/                          # manual 500 RPS harness, not run in CI
├── docs/lld/iam-lld-authz-enrichment.md  # Low-Level Design — §16 AE-# decision register, the source every §3.1/§4.2/etc. reference in this codebase points back to
├── docs/architecture/mermaid/         # 7 .mmd sources — layer-model, package-dependencies, request-flow, cache-strategy, event-flow, failure-handling, observability-stack
├── scripts/init-localstack.sh         # creates the 5 inbound queues + their -dlq's
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
    github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon v1.3.0
    github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events    v1.4.0
)
```

- `platform-gincommon` — `pkg/logger` (zap + redaction), `pkg/grpccommon` (`ObservabilityUnaryInterceptors`: panic-recovery → request-id → tracing → metrics → logging). **Not** `ProtectedUnaryInterceptors` — Envoy calls this service over mTLS, not as a JWT-bearing client, so there's no bearer auth to require.
- `platform-events` — `pkg/events` SQS consumer loop (`NewSQSConsumer`, `WithMaxReceiveCount`, `WithConcurrency`, `WithDrainTimeout`).

**Not a dependency:** `platform-pgcommon` (no database), `platform-schemagov` (this service publishes no events, so there's nothing to schema-govern).

### Dependency rules (enforced in CI via `go-arch-lint`)

- `domain` imports nothing outside itself; `domain/policy` imports only `domain`. `config` imports nothing internal at all.
- `usecase` imports only `domain` and `domain/policy` — **never** `config` (TTLs/timeouts arrive as plain constructor parameters, not a config import — see `usecase/ports.go`'s own doc comment).
- `adapter/inbound/*` calls into `usecase` (it's the orchestration layer Envoy's gRPC adapter calls into) — this is the one place the dependency direction differs from `iam-user-profile`'s `core/service`-layer naming; there is no separate `port` package here, `usecase/ports.go` plays that role. One exception: the AsyncAPI viewer (`internal/adapter/inbound/http/asyncapi.go`) reads the embedded spec directly from the `api` package (the compiled-in `api/asyncapi.yaml`, §`api/embed.go`) rather than through `usecase` — the one inbound-adapter dependency besides `usecase`/`domain`/`policy` `.go-arch-lint.yml` allows.
- `adapter/outbound/*` implements `usecase`'s port interfaces; nothing in `domain` or `usecase` imports an adapter.

## Key Files to Know

- **`cmd/server/main.go`** — wiring; `gin.SetMode(gin.ReleaseMode)` outside `APP_ENV=dev` (same convention as `iam-org-membership`/`iam-user-profile`) — found missing entirely by actually running the built binary end-to-end rather than by static analysis; without it, every deployment including production ran Gin in permanent debug mode (per-route registration spam on every startup, Gin's own "switch to release mode" warning in the logs forever). gRPC server gets `reflection.Register(grpcServer)` when `cfg.AppEnv != "production"` (lets `grpcurl`/`grpcui` discover `Check` without a local `.proto` copy), plus a native `grpc.health.v1.Health` service tied to the same `MarkReady()` signal as HTTP `/healthz`. Listens in plaintext unless `GRPC_TLS_CERT_FILE`/`GRPC_TLS_KEY_FILE` are set (`loadServerTLS`) — see the file's comment on why "Envoy calls over mTLS" is an unverified deployment assumption, not something this server enforces. `grpc.MaxRecvMsgSize`/`MaxSendMsgSize` are set well below the 4MiB default (defense-in-depth, `CheckRequest`/`CheckResponse` are small). The HTTP server (health/readiness only) and the `/metrics` server are two separate `http.Server`s on two separate ports/listeners. Background workers: 5 SQS consumers via `startConsumers`, each idle (no-op) if its queue URL env var is blank, each built with its own `events.WithConcurrency(n)` (`*_AUTHZ_QUEUE_CONCURRENCY` env vars, default 4 — `platform-events`' own default is 1, fully serial per queue), plus `runReceiveErrorWatchdog` (`receive_watchdog.go`) started alongside them as a safety net for a consumer stuck with no successful `ReceiveMessage` — see that file's own entry below. **`fatalErr` (LLD §16 AE-28)**: a single shared, 1-buffered channel fed by every background-failure source in this process — `startConsumers`' goroutines, `runReceiveErrorWatchdog`, and (since `deploy/helm/values.yaml`'s liveness/readiness probes are `httpGet` against the HTTP server only, with no `grpc:` probe on the gRPC port) now also the gRPC/HTTP/metrics server goroutines' own non-graceful `Serve`/`ListenAndServe` exits via a small `reportFatal` helper — closing a gap where a dead gRPC server (100% of Envoy's traffic) could run forever behind a `/healthz` that never noticed. `main()`'s shutdown `select` treats `<-fatalErr` identically to `<-quit`. Shutdown order: gRPC `GracefulStop` → HTTP `Shutdown` → metrics server `Shutdown` → consumers `Stop()` **concurrently** (a `sync.WaitGroup`, not a sequential loop — bounds worst-case shutdown to one drain window instead of five) → `cancelBackgroundWork` → `cache.Close()`.
- **`internal/usecase/check.go`** — `check()` implements the full §3.1 chain; **judgment call**: MFA-freshness call failure maps to `DenyMFAStale`, not `DenyServiceUnavailable` (documented inline — a sibling outage on this specific check is treated as "can't confirm freshness" rather than "service down"). `resolveContext`'s outcome switch uses `default:` + `//nolint:exhaustive` rather than an explicit `case OutcomeNormal` — `SiblingReachable: false` is hardcoded at that call site, so `OutcomeNormal` can never actually occur there; an explicit per-value case would compile only with a trailing statement Go's compiler can't prove unreachable, which permanently blocks 100% coverage. Don't "fix" this by re-enumerating the case.
- **`internal/usecase/failure.go`** — `DecideDependencyOutcome()` is the §7 table as a pure function, deliberately its own package-level function (not scattered in adapter code) so the test suite can exercise every row directly. The tender-ACL overlay's fail-closed rule is independent of this table — checked separately in `check.go`.
- **`internal/adapter/outbound/valkey/cache.go`** — `mfa_freshness_seconds` is **never** written here — hard invariant, has a dedicated regression test. Any change that folds MFA freshness into the `ae:ctx` envelope is a security regression, not a refactor.
- **`internal/usecase/invalidate.go`** — `HandleUserDeleted` and `HandleMembershipRevoked` share the same best-effort-tender-ACL-eviction shape: `EvictTenderACLForUser` failure logs a warning but never fails the event, since a partial scan degrades to "stale until its 15s TTL expires", not a correctness failure requiring retry. `HandleMembershipRevoked` (LLD §16 AE-20) exists because a whole-membership removal soft-deletes the `tenant_memberships` row and leaves per-grant rows inert rather than firing individual `*Revoked` events — it's the only `membership-authz-q` event type that needs the wider eviction the other five don't.
- **`internal/adapter/inbound/consumer/idempotency.go`** — `processedHandler()` marks-then-handles (`MarkProcessed`, SET NX — the atomic check *is* the duplicate check, no separate `IsProcessed` step exists or is needed); on handler failure it calls `Cache.EvictProcessed()` to undo the mark, or a failed message would be falsely treated as already-processed on redelivery and silently skipped instead of retried (this was a real bug, caught by `TestSQS_DLQ_MessageMovesAfterMaxReceiveCount` timing out — see `TestDedupingHandler_RetriesAfterHandlerFailure`).
- **`cmd/server/receive_watchdog.go`** — verified against the vendored `platform-events` source that its SQS consumer's `Start()` never returns an error for a persistently failing `ReceiveMessage` loop (revoked IAM permissions, a deleted queue) — it retries forever internally, so the existing `fatalErr` restart channel never fires for that failure mode on its own. This file closes the gap by polling `sqs_receive_errors_total` per queue and pushing to `fatalErr` after `staleAfter` (6) consecutive polls with no successful receive. `poll()` deduplicates by queue URL before updating streak state — two friendly queue names racing to update/reset the same URL's counter within one poll would otherwise make that URL's stuck consumer permanently undetectable; `config.go`'s duplicate-queue-URL fail-fast check (above) is the other half of that same defense.
- **`internal/adapter/inbound/grpc/claims.go`** — `decodeClaims()` reads only `req.Attributes.MetadataContext[cfg.Namespace].Fields[cfg.PayloadKey]` — never `req.Attributes.Request.Http.Headers`. A code path that falls back to headers is an identity-spoofing vulnerability, not a convenience fix.
- **`internal/adapter/inbound/grpc/requestfacts.go`** — `tenderIDFromPath()` parses `tender_id` out of `req.Attributes.Request.Http.Path`'s `/tenders/{id}` segment; it is deliberately **not** one of the `ContextExtensions` keys (§16 AE-22 in the LLD). `ExtAuthzPerRoute.check_settings.context_extensions` is a static `map<string,string>` an Envoy route author writes once per route at config time — it has no per-request templating, so it cannot carry a genuine per-resource ID the way it can a route-invariant fact like `policy_action`. Every tender-scoped route (GET/POST/PUT/PATCH/DELETE alike) must keep the tender ID in the URL path — a body-only ID silently disables the tender-ACL overlay for that route instead of erroring.
- **`internal/adapter/inbound/http/router.go`** / **`asyncapi.go`** — the AsyncAPI HTML viewer (`GET /asyncapi`) and raw-spec endpoint (`GET /asyncapi.yaml`), gated by `DocsConfig` (`Environment`/`Enabled`/`AuthToken`): always mounted outside `APP_ENV=production`, opt-in via `DOCS_ENABLED` in production, optionally bearer-token-gated via `DOCS_AUTH_TOKEN`. Ported verbatim from `iam-tender-acl`'s identical renderer — entirely YAML-driven off the embedded `api/asyncapi.yaml`, no service-specific logic. No Swagger half, since this service has no business HTTP API to document one for. `asyncapi.go`'s description/summary truncation **must** go through `truncateRunes` (rune-boundary-safe), never a bare `s[:N]` slice — this was a real bug: `api/asyncapi.yaml`'s `info.description` uses multi-byte box-drawing characters (`─`, U+2500) to draw its producer table, a byte-level `s[:800]` cut landed mid-character, and the `/asyncapi` page rendered `�` (U+FFFD) instead of the description. Caught by `TestAsyncAPIHandler_RealSpec_NeverEmitsReplacementCharacter`, which renders the real embedded spec and asserts no `�` appears anywhere in the output.
- **`internal/adapter/outbound/metrics/recorder.go`** — `New(reg ...prometheus.Registerer)` defaults to `prometheus.DefaultRegisterer` when called with no args, but `cmd/server` passes `gincommon.MetricsRegisterer()` so the `authz_*` business counters are explicitly confirmed to land on the same registry as `platform-gincommon`'s own metrics (same convention as `iam-user-profile`). Tests call `newRecorder(reg)` directly with an isolated `prometheus.NewRegistry()` so parallel tests don't collide on the default registry.
- **`test/fixtures/cache.go`** — `FakeCache` has a `*Err` field per operation (`SetCtxErr`, `GetTenderACLErr`, `EvictProcessedErr`, …) for error-injection tests; it does not use gomock/mockery, matching `iam-user-profile`'s convention.

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

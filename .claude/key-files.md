# Key Files to Know

Per-file invariants, security notes, and judgment calls. Read this file when working on a specific component.

## cmd/server/main.go

Composition root. `gin.SetMode(gin.ReleaseMode)` outside `APP_ENV=dev` — found missing by running the binary end-to-end; without it every deployment ran Gin in permanent debug mode. gRPC server gets `reflection.Register` when `cfg.AppEnv != "prod"`. Listens in plaintext unless `GRPC_TLS_CERT_FILE`/`GRPC_TLS_KEY_FILE` are set (`loadServerTLS`) — "Envoy calls over mTLS" is an unverified deployment assumption. `grpc.MaxRecvMsgSize`/`MaxSendMsgSize` set well below 4MiB default (defense-in-depth). HTTP server (health/readiness) and `/metrics` server are two separate `http.Server`s on two ports.

**`fatalErr` (LLD §16 AE-28):** single shared 1-buffered channel fed by every background-failure source — `startConsumers` goroutines, `runReceiveErrorWatchdog`, and gRPC/HTTP/metrics server goroutines' non-graceful exits via `reportFatal`. A dead gRPC server can't run forever behind `/healthz`'s httpGet-only probe. `run()` returns the fatal cause after graceful shutdown so the process exits non-zero (SIGTERM still exits 0); `test/e2e/startup_test.go` pins both.

**Shutdown order:** gRPC `GracefulStop` → HTTP+metrics `Shutdown` → consumers `Stop()` **concurrently** (a `sync.WaitGroup`, not sequential — bounds worst-case to one drain window instead of five) → `cancelBackgroundWork` → `cache.Close()`.

**LLD §16 AE-33:** `GracefulStop` and HTTP+metrics `Shutdown()` are each timeout-bounded (`grpcGracefulStopTimeout`/`httpShutdownTimeout`, 10s each). A wedged Envoy connection used to stall every later step until `terminationGracePeriodSeconds` (60s) forced SIGKILL, skipping the consumer drain. Rebalanced worst case: 10+10+35=55s, fits with 5s margin. **Do not restore a flat 30s timeout or unbounded `GracefulStop`.**

**Background workers:** 5 SQS consumers via `startConsumers` (each idle/no-op if queue URL blank), each with `events.WithConcurrency(n)` (`*_AUTHZ_QUEUE_CONCURRENCY` env vars, default 4 — platform-events' own default is 1, fully serial). Plus `runReceiveErrorWatchdog`.

## cmd/server/receive_watchdog.go

`platform-events`' SQS consumer `Start()` never returns an error for a persistently failing `ReceiveMessage` loop — it retries forever internally. This file closes the gap: each consumer gets its own `receiveTrackingClient` (decorator over `*sqs.Client`) that counts that consumer's errors/successes. Watchdog pushes to `fatalErr` after `staleAfter` (6) consecutive 30s polls with new errors and no successful receive.

Does NOT read a metric back from the Gatherer — platform-events' former per-queue SQS counter was removed; its successor has no `queue` label and is fail-soft. Each consumer has its own tracker so two queues sharing a URL can't reset each other's streak; `config.go`'s duplicate-URL check still rejects that at startup.

## internal/usecase/check.go

`check()` implements the full §3.1 chain, starting with empty-subject → `DENY_MALFORMED_IDENTITY` (§8.1, LLD rev 1.31). `grpc.Server.Check` does **not** short-circuit this — the deny must be timed and counted in `decisions_total`/`deny_reason_total` like every other. Don't move it back into the adapter.

**Judgment call:** MFA-freshness call failure maps to `DenyMFAStale`, not `DenyServiceUnavailable` — a sibling outage on this check is treated as "can't confirm freshness", not "service down".

**`resolveContext` outcome switch:** uses `default:` + `//nolint:exhaustive` rather than explicit `case OutcomeNormal` — `SiblingReachable: false` is hardcoded at that call site so `OutcomeNormal` can never occur; an explicit per-value case would permanently block 100% coverage. Don't "fix" this by re-enumerating.

**Concurrent Valkey reads:** `GetMembershipContext`/`GetTenantContext` run concurrently (two goroutines + `sync.WaitGroup`). At the 10ms default `VALKEY_READ_TIMEOUT`, two sequential reads could alone approach the 15ms p99 decision budget (§11.1). Verified race-clean (`-race -count=5`).

**Singleflight-coalesced I-8 call runs on `context.WithoutCancel(ctx)`** (LLD rev 1.32): under the first caller's context, Envoy cancelling one request failed every request waiting on the same key (`TestCheck_Singleflight_FirstCallerCancelled_OthersUnaffected`). Don't pass the request `ctx` into `sf.Do`.

**Security invariant — future `auth_time` (LLD §16 AE-38):** `checkMFAFreshness()` guards `authTime.After(c.now())` before the duration comparison — a future auth_time produces a negative duration that would silently pass the MFA gate without this guard.

**Security invariant — empty TenderID (AE-39):** if `reqFacts.RequiredAccessLevel != ""` but `reqFacts.TenderID == ""` (e.g. trailing-slash `/tenders/` or route misconfiguration), `check()` returns `DenyMalformedIdentity` immediately rather than silently skipping the tender-ACL overlay. TAC-4 call failures fail closed to `DenyTenderACLInsufficient` (§7 row 4) and call `ObserveTACDependencyError()`.

**Sibling timeouts** must never be set below the siblings' own p99 targets (AE-37: I-8 40ms, TAC-4 30ms). `GRPC_REQUEST_TIMEOUT` caps each `Check` server-side.

**Two Valkey clients:** request-path `cache` (10ms `VALKEY_*_TIMEOUT`) and `eventCache` (`cache.WithTimeouts(VALKEY_EVENT_TIMEOUT)`, 500ms) for everything SQS consumers write — the invalidator, `ae:processed` ledger, and `SetRealm`/`SetRestricted` via `cmd/server/factstore.go`. Don't bind consumer writes to the 10ms client: one slow round trip costs a 30s visibility-timeout retry.

The e2e harness pins `SQS_WAIT_SECONDS=1` / `SQS_VISIBILITY_TIMEOUT=5s` for isolation — don't remove them.

## internal/usecase/failure.go

`DecideDependencyOutcome()` is the §7 table as a pure package-level function (not scattered in adapter code) so the test suite can exercise every row directly. The tender-ACL overlay's fail-closed rule is independent of this table — checked separately in `check.go`.

## internal/usecase/invalidate.go

`NewInvalidator(cache, realmMap, restricted, log, recorder ...Recorder)` takes an optional variadic `Recorder` (defaults to `NoopRecorder{}`; `cmd/server` passes the real one).

`HandleUserDeleted` and `HandleMembershipRevoked` share the same best-effort-tender-ACL-eviction shape: `EvictTenderACLForUser` failure calls `recorder.ObserveEvictionError(eventType)` and logs a warning but never fails the event — a partial scan degrades to "stale until its 15s TTL expires", not a correctness failure requiring retry.

`HandleMembershipRevoked` (LLD §16 AE-20) exists because a whole-membership removal soft-deletes the `tenant_memberships` row and leaves per-grant rows inert rather than firing individual `*Revoked` events — it's the only `membership-authz-q` event type needing the wider eviction.

## internal/adapter/outbound/valkey/cache.go

`mfa_freshness_seconds` is **never** written here — hard invariant, has a dedicated regression test. Any change that folds MFA freshness into the `ae:ctx` envelope is a security regression, not a refactor.

## internal/adapter/inbound/consumer/idempotency.go

`processedHandler()` marks-then-handles via `skipDuplicate` (`MarkProcessed`, SET NX — the atomic check *is* the duplicate check; no separate `IsProcessed` step). On handler failure it calls `Cache.EvictProcessed()` to undo the mark — without this, a failed message would be falsely treated as already-processed on redelivery and silently skipped (real bug, caught by `TestSQS_DLQ_MessageMovesAfterMaxReceiveCount` timing out; see `TestDedupingHandler_RetriesAfterHandlerFailure`).

`dedup.go`'s `ackUnknown` is the forward-compat path for an unwired event type (log + ack; wrapper already claimed the ID).

**LLD §16 AE-34:** `defer`/`recover()` around the handler call does the identical `EvictProcessed` cleanup for a **panic**, then re-panics so `platform-events`' own recovery still runs. A panic used to bypass eviction — for most queues this just left a stale cache entry, but for `tender-authz-q` it permanently disabled the tender-ACL overlay for that tender (`ae:restricted` has no TTL, §8.5.1).

## internal/config/config.go

Every `envInt`-backed field that can silently misbehave on zero/negative goes through `envPositiveInt` (`GRPC_MAX_CONCURRENT_STREAMS`, both gRPC message-size limits, all five `*_AUTHZ_QUEUE_CONCURRENCY` vars) — should crash-loop the pod at startup, not surface as a confusing runtime symptom.

`GRPC_MAX_CONCURRENT_STREAMS` gets an explicit `math.MaxUint32` range check before `uint32(streams)` narrowing — an oversized value would otherwise wrap silently.

`GRPC_REQUEST_TIMEOUT` and `VALKEY_EVENT_TIMEOUT` must be positive. A `VALKEY_URL` containing `://` must pass `redis.ParseURL` (LLD rev 1.32) — the cache adapter otherwise falls back to treating it as `host:port`, so a typo'd `rediss://` URL starts with TLS silently off and, since `/readyz` ignores Valkey, fails every request closed.

All five non-dev fail-fasts live here, not in `main.go`, so `config_test.go` can unit-test them: dev-default sibling URLs, `VALKEY_URL` must be `rediss://`, both `SHARED_REALM_ISSUER` and `REALM_TENANT_MAP_SEED` empty, blank queue URLs, duplicate queue URLs. `AE_PROCESSED_EVENT_TTL` defaults to 192h (PE-1 — strictly > the 7-day SQS lifetime); `AE_STALE_IF_ERROR_MAX_AGE` is hard-capped at 5m (§7).

`ResolveAppEnv()` (`APP_ENV` → `ENVIRONMENT` → `dev`, trimmed/lowercased) is the single environment source — never read `APP_ENV` directly.

## internal/adapter/inbound/grpc/claims.go

`decodeClaims()` reads **only** `req.Attributes.MetadataContext[cfg.Namespace].Fields[cfg.PayloadKey]` — never `req.Attributes.Request.Http.Headers`. A code path that falls back to headers is an **identity-spoofing vulnerability**, not a convenience fix.

## internal/adapter/inbound/grpc/requestfacts.go

`tenderIDFromPath()` parses `tender_id` out of `req.Attributes.Request.Http.Path`'s `/tenders/{id}` segment. It is deliberately **not** one of the `ContextExtensions` keys (§16 AE-22). `ExtAuthzPerRoute.check_settings.context_extensions` is a static `map<string,string>` — no per-request templating, so it can't carry a per-resource ID like a route-invariant `policy_action` can. Every tender-scoped route must keep the tender ID in the URL path — a body-only ID silently disables the tender-ACL overlay.

## internal/adapter/inbound/http/router.go and asyncapi.go

AsyncAPI HTML viewer (`GET /asyncapi`) and raw-spec endpoint (`GET /asyncapi.yaml`), gated by `DocsConfig` (`Environment`/`Enabled`/`AuthToken`): always mounted outside `APP_ENV=prod`, opt-in via `DOCS_ENABLED` in prod, optionally bearer-token-gated via `DOCS_AUTH_TOKEN`. No Swagger half (no business HTTP API).

`asyncapi.go`'s description/summary truncation **must** go through `truncateRunes` (rune-boundary-safe), never a bare `s[:N]` slice — this was a real bug: `api/asyncapi.yaml`'s `info.description` uses multi-byte box-drawing characters (`─`, U+2500); a byte-level cut landed mid-character, rendering `<EFBFBD>` (U+FFFD). Caught by `TestAsyncAPIHandler_RealSpec_NeverEmitsReplacementCharacter`.

## internal/adapter/outbound/metrics/recorder.go

`New(reg)` builds every `iam_authz_enrichment_*` metric through gincommon's Tier 3 constructors, which validate names/labels against the Platform Observability Registry and **require gincommon's metrics identity to exist first** (`cmd/server` calls `ObservabilityMiddlewares` before `metrics.New`; the test file's `TestMain` does the same). Returns an error naming every failing metric instead of panicking.

`deny_reason_total{reason}` emits the `DenyReason` **lowercased** (`deny_service_unavailable`) — the registry's `reason` vocabulary is snake_case. `TestNew_AppliesGincommonConstLabels` emits every series and runs `obsregistry.Validate`. Keep it emitting every metric, or a new label violation goes unnoticed.

Two error counters sit beside the latency/decision series: `iam_authz_enrichment_tac4_errors_total` (`ObserveTACDependencyError()`, `check.go`'s TAC-4 error path — tells an iam-tender-acl outage from real `DENY_TENDER_ACL_INSUFFICIENT` denials; alerted by `AuthzEnrichmentTAC4ErrorSpike`) and `iam_authz_enrichment_eviction_errors_total{event}` (`ObserveEvictionError(event)`, `invalidate.go`'s best-effort SCAN failure path). `BatchTenderACLClient` is a separate port from `OrgMembershipClient` — it holds only `GetBatchTenderACL`, so §3.1 Check() fakes don't implement a method no Check() path calls. `domain.TenderACL.AccessLevel` is `*string` — an absent JSON field decodes as nil, not "" (TAC-GAP-001).

## test/fixtures/cache.go

`FakeCache` has a `*Err` field per operation (`SetCtxErr`, `GetTenderACLErr`, `EvictProcessedErr`, …) for error-injection tests. Does not use gomock/mockery.

## test/e2e/main_test.go

`TestMain` builds the fake Org & Membership/Tender ACL server, starts the real compiled binary (`E2E_BINARY_PATH`, default `../../bin/iam-authz-enrichment` — `make build` first) as a subprocess with SIGTERM-then-Kill teardown, and dials it over a real gRPC connection before running any test.

**`runID`/`id()`:** every tenant/tender name a test constructs must go through `id()` (suffixes a per-process UUID) — this suite runs against a real, persistent Valkey, and `ae:restricted` has no TTL by design (§8.5.1). An unscoped name lets one run's residual state corrupt a later run's "not yet restricted" assertion.

**`fakeorg.go`'s `tenderACLFixture.ExpiresAt` must stay `time.Time`, never `string`** — the real client decodes TAC-4's response into `domain.TenderACL{ExpiresAt time.Time}`; an empty-string JSON value fails the unmarshal, indistinguishable from any other `GetTenderACL` error, and fails closed to `DENY_TENDER_ACL_INSUFFICIENT` — a mock bug that looks exactly like a real denial.

**Never name a file in this package `mockorg*`** (or anywhere else in the repo) — `.gitignore`'s `mockorg*` rule glob-matches that basename anywhere in the tree. A file named `mockorg.go` was silently excluded from every `git add`, passed locally, and broke in CI's fresh checkout with `undefined: mockOrg`. Use `fakeorg.go`/`fakeOrg` instead.

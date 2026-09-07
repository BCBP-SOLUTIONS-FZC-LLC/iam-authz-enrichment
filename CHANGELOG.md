# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

This service has no production deployment yet — pre-1.0, still in active development.

### Added
- `VERSIONING.md` — SemVer rules and release process for the runtime contract (`DenyReason` values, injected headers, `CheckRequest` field usage, env vars, `values.yaml` shape).
- `api/asyncapi.yaml` — event-contract spec (5 consumed queues, 15 event types, 0 published), served live at `GET /asyncapi`/`GET /asyncapi.yaml` (`DOCS_ENABLED`/`DOCS_AUTH_TOKEN`).
- `authz_i14_call_latency_seconds` metric (MFA-freshness/I-14 call latency), matching the existing I-8/I-12 histograms.
- `MembershipRevoked` subscription on `membership-authz-q` (LLD §16 AE-20) — evicts `ae:ctx`/`ae:neg`/`ae:tender_acl` on a whole-membership removal.
- `TENDER_ACL_BASE_URL`/`TENDER_ACL_TIMEOUT` — tender-ACL checks now call `iam-tender-acl` directly instead of Org & Membership (ADR-0007 Wave 3 Phase 4).
- Fail-fast startup validation: refuses to start if `ORG_MEMBERSHIP_BASE_URL`/`TENDER_ACL_BASE_URL` is left at its dev default outside `APP_ENV=dev`.
- Optional app-level gRPC TLS/mTLS (`GRPC_TLS_CERT_FILE`/`_KEY_FILE`/`_CLIENT_CA_FILE`).
- Native `grpc.health.v1.Health` service alongside HTTP `/healthz`.
- `GRPC_MAX_RECV_MSG_SIZE_BYTES`/`_SEND_` limits (256KiB, defense-in-depth).
- Per-queue SQS consumer concurrency env vars (`*_AUTHZ_QUEUE_CONCURRENCY`, default 4 each).
- `deploy/monitoring/dlq-alarms.tf.example` + `docs/runbook.md`.
- `.github/workflows/release.yml` (tag-triggered image build/scan/sign/publish) + reusable `validate-test.yml`/`validate-quality.yml`.
- Real `test/load` baseline numbers: 500 RPS, hit p99=1.68ms, miss p99=3.18ms (single-machine, not production-validated).
- `AE_RESTRICTED_NEG_TTL`/`AE_REALM_NEG_TTL` (default 5s each) — negative-cache TTLs for `RestrictedTenderSet`/`RealmMap`'s L1 caches, decoupled from `AE_NEG_TTL`.
- Fail-fast startup validation: refuses to start if all five `*_AUTHZ_QUEUE_URL` vars aren't set outside `APP_ENV=dev`, or if any two of them are set to the same URL.
- `cmd/server/receive_watchdog.go` — polls `sqs_receive_errors_total` per queue and triggers the existing pod-restart path if a consumer has had no successful `ReceiveMessage` for several minutes straight, a failure mode `consumerFatal` could not otherwise detect (the underlying SQS consumer library retries a persistently failing receive loop forever without ever returning an error).

### Changed
- `RestrictedTenderSet`/`RealmMap` now cache negative ("not restricted" / "no such realm") results in L1 with a TTL, instead of hitting Valkey on every `Check()` for a tender/issuer that has never resolved.
- `/metrics` moved off `APP_PORT` to its own dedicated port (`METRICS_PORT`, default 9090).
- `deploy/helm/values.yaml` replica/HPA range corrected to 5–20 to match the LLD's design commitment.
- SQS consumer shutdown parallelized (`sync.WaitGroup`) instead of sequential, bounding worst-case shutdown time.
- `release.yml`'s `deploy-gate` uses a gRPC-specific health query and only runs when `DEPLOY_GATE_ENABLED=true` (default skipped — no cluster provisioned yet).
- Bumped `platform-gincommon` to v1.3.0; the HTTP router now goes through `gincommon.ObservabilityMiddlewares` instead of a bare `gin.New()`.
- Bumped all direct dependencies to their latest available versions (`go get -u ./...` + `go mod tidy`): `aws-sdk-go-v2` family (1.43.5/1.32.36/1.19.35/1.46.5 → 1.46.0/1.33.3/1.20.3/1.51.0), `go.opentelemetry.io/otel`(`/trace`) 1.45.0 → 1.46.0, `envoyproxy/go-control-plane/envoy` 1.37.0 → 1.39.0, `stretchr/testify` 1.11.1 → 1.12.1, `alicebob/miniredis/v2` 2.38.0 → 2.39.0, `prometheus/client_model` 0.6.2 → 0.6.3, `google.golang.org/grpc` 1.83.0 → 1.83.2, plus the `golangci-lint/v2` tool directive 2.12.2 → 2.13.2. `platform-events`/`platform-gincommon` (the two private `BCBP-SOLUTIONS-FZC-LLC` modules) were already at their latest published tags. No API-breaking changes encountered; `make ci` (fmt/vet/lint/arch-lint/race tests/100% coverage/build) and `make vuln-check` pass unchanged.

### Fixed
- Dockerfile's pinned builder image (`golang:1.26.5-alpine`) was one patch version behind `go.mod`'s `go 1.26.6` requirement, so `docker build` failed immediately at `go mod download` with `go: go.mod requires go >= 1.26.6 (running go 1.26.5; GOTOOLCHAIN=local)` — every image build was broken, not just a local dev inconvenience. Fixed by re-pinning to `golang:1.26.6-alpine` (fresh digest). `make pin-base-images` now derives the golang image tag from `go.mod`'s own `go` directive instead of a second hardcoded version string in the `Makefile`, so a future `go.mod` bump and this pin can't silently drift apart again the same way.
- `/asyncapi` HTML viewer rendered `�` instead of the description — byte-level string truncation split multi-byte UTF-8 characters. Fixed with a rune-boundary-safe `truncateRunes` helper.
- `api/asyncapi.yaml`'s producer-summary table incorrectly listed the same combined producer for `billing-authz-q` and `tenant-authz-q`; corrected to each queue's actual distinct producer.
- A few CI script bugs: a hadolint false-positive on `ENV GOPRIVATE`, a SIGPIPE in `extract-release-notes.sh`, and `export-image-provenance.sh` reading provenance attestations with the wrong tool.
- Gin never switched out of debug mode outside `APP_ENV=dev` — unlike `iam-org-membership`/`iam-user-profile`, nothing in `cmd/server/main.go` called `gin.SetMode(gin.ReleaseMode)`, so every deployment (including production) ran Gin in debug mode: per-route registration spam on every startup and Gin's own "switch to release mode" warning in the logs permanently. Found by actually running the built binary end-to-end (grpcurl/curl walkthroughs, both `APP_ENV=dev` and `=production`) rather than by static analysis. Fixed by adding the same `if cfg.AppEnv != "dev" { gin.SetMode(gin.ReleaseMode) }` guard the sibling services already use.
- **I-8 wire-format mismatch**: `internal/adapter/outbound/orgmembership/client.go`'s `departmentDTO.Level` was tagged `json:"level"`, but Org & Membership's real I-8 response uses `"role_level"` for the same field (verified against that service's actual `GetMemberships` handler and its own LLD's documented example). Every department's level silently decoded as `""` on every real request, corrupting the `x-departments` header (`department_id:` instead of `department_id:level`) and permanently failing any `required_department_level` policy gate — fail-closed, not an authorization bypass, but a live functional/interoperability defect. This service's own contract test and README's mock-Org-&-Membership walkthrough had independently encoded the same wrong field name, which is why nothing caught it; both corrected alongside the fix. Verified end-to-end against a running binary with a corrected mock.
- `api/asyncapi.yaml`, `README.md`, and the LLD stated no published `asyncapi.yaml` was available to verify Realm Provisioner's `TenantConverted`/`TenantRealmReady` event schemas against — stale: the spec is present in this workspace and, checked field-for-field, matches this service's decoding exactly (`realm: {type: string}` both sides). `producer-lifecycle-status` upgraded `unknown` → `stable` for both messages; documentation-only, no behavior change (LLD §16 AE-27).
- **gRPC/HTTP/metrics server death after startup was invisible to both health probes and the pod-restart path.** `deploy/helm/values.yaml`'s liveness/readiness probes are `httpGet` against the HTTP server only — there is no `grpc:` probe against the native health service on the gRPC port. `main.go`'s three server goroutines only logged an unexpected `Serve`/`ListenAndServe` exit; nothing fed it to the existing `consumerFatal` restart channel. An unexpected death of `grpcServer.Serve` — the entire ext_authz decision path, 100% of Envoy's traffic — would leave `/healthz`/`/readyz` reporting healthy forever with no pod restart: a total, silent outage. Fixed by routing all three servers' non-graceful exits into the same shared fatal-error channel (renamed `fatalErr`) via a `reportFatal` helper, reusing the identical restart path a consumer death or the receive-error watchdog already trigger (LLD §16 AE-28).
- **Critical: every I-8/I-14 call to Org & Membership was missing required internal-service-identity headers.** Org & Membership's `/internal/*` routes (I-8 `GetMemberships`, I-14 `GetMFAFreshness`) are gated by an application-level `RequireSystemRole()` check requiring `x-user-id: iam-system` / `x-tenant-id: <tenant>` / `x-tenant-roles: iam-system` — the same convention that service's own five outbound clients to sibling internal APIs all use. This client sent none of them. **Impact was total, not partial**: every real (non-mocked) call would 403 before reaching the handler, so the core cache-miss-rebuild path could never succeed against a real Org & Membership instance — undetected because every mock used so far (including this project's own tests and README walkthrough) doesn't reimplement the callee's auth middleware, so it accepted requests regardless of headers sent. Fails closed (degrades/denies via the existing §7 failure matrix), never a bypass. Fixed by setting all three headers on `GetMemberships`/`GetMFAFreshness`; `GetTenderACL` (TAC-4, mesh-only/no-RBAC on `iam-tender-acl`'s side) deliberately continues to send none, with a dedicated regression test guarding the distinction. Verified against a running binary and a hand-built mock that reimplements Org & Membership's exact `RequireSystemRole` check (403 without the fix, 200 with it).

### Removed
- `active_delegations[]` / `domain.Delegation` — dropped entirely; delegation state moved to its own service (`iam-delegation`, ADR-0008).

## [0.1.0] - 2026-08-12

### Added
- Initial implementation of the `iam-authz-enrichment` Envoy `ext_authz` Policy Decision Point: §3.1 precedence chain, §4 Valkey caching, §5 event consumption, §7 failure-handling matrix, §10 observability.
- Trivy CVE scan, a dedicated smoke-test job, and a GHCR image publish (SBOM + provenance attestations, Cosign keyless signing) in CI.
- `deploy/helm/` chart, `deploy/iam/` reference IAM policy, and `deploy/monitoring/` Prometheus alerting rules for platform deployment.
- Tests covering `valkey.Cache.SetTenderACL`'s JSON-marshal-error branch and `EvictTenderACLForUser`'s DEL-fails-after-successful-SCAN branch.

### Changed
- Raised the CI coverage gate from ≥97% to 100% (`.github/scripts/coverage-gate.sh`, `ci.yml`).
- `test`/`quality` job display names in `ci.yml` now read "Validate / Test / test" / "Validate / Quality / quality" to match the org-required status check names.

### Fixed
- `usecase.Checker.resolveContext`'s dependency-outcome switch had two lines of structurally
  unreachable code (an explicit `OutcomeNormal` case that can never occur at that call site,
  plus a trailing defensive fallback Go's compiler required because the switch had no
  `default`). Replaced with `default:` (same fail-closed behavior, reachable) and a targeted
  `//nolint:exhaustive` — this was the last blocker to 100% coverage.

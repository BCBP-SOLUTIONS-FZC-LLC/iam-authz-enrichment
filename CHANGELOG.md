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

### Changed
- Renamed all Prometheus metrics from `authz_*` to `iam_authz_enrichment_*` per the Enterprise Platform Observability Standard three-tier taxonomy (Tier 3 service-specific namespace, with `service` and `environment` ConstLabels injected centrally).
- Consolidated three separate dependency-call histograms (`authz_i8_call_latency_seconds`, `authz_i12_call_latency_seconds`, `authz_i14_call_latency_seconds`) into a single `iam_authz_enrichment_dependency_request_seconds{dependency}` HistogramVec.
- Added Tier 1 platform-shared metrics: `platform_messages_received_total`, `platform_messages_processed_total`, `platform_messages_failed_total` (with `domain="iam"`, `service`, `environment` ConstLabels) for SQS consumer instrumentation.
- Added `metric-lint` CI target (`make metric-lint`) enforcing the namespace naming rules.
- Updated Prometheus alert rules, HPA adapter config, and PrometheusRule Helm template to use the new canonical metric names.
- `/metrics` moved off `APP_PORT` to its own dedicated port (`METRICS_PORT`, default 9090).
- `deploy/helm/values.yaml` replica/HPA range corrected to 5–20 to match the LLD's design commitment.
- SQS consumer shutdown parallelized (`sync.WaitGroup`) instead of sequential, bounding worst-case shutdown time.
- `release.yml`'s `deploy-gate` uses a gRPC-specific health query and only runs when `DEPLOY_GATE_ENABLED=true` (default skipped — no cluster provisioned yet).
- Bumped `platform-gincommon` to v1.3.0; the HTTP router now goes through `gincommon.ObservabilityMiddlewares` instead of a bare `gin.New()`.

### Fixed
- `/asyncapi` HTML viewer rendered `�` instead of the description — byte-level string truncation split multi-byte UTF-8 characters. Fixed with a rune-boundary-safe `truncateRunes` helper.
- `api/asyncapi.yaml`'s producer-summary table incorrectly listed the same combined producer for `billing-authz-q` and `tenant-authz-q`; corrected to each queue's actual distinct producer.
- A few CI script bugs: a hadolint false-positive on `ENV GOPRIVATE`, a SIGPIPE in `extract-release-notes.sh`, and `export-image-provenance.sh` reading provenance attestations with the wrong tool.

### Deprecated
- `authz_*` metric names are now deprecated and emitted in parallel for backward compatibility. They will be removed after dashboards and alert rules have migrated.

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

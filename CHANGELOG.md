# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `.github/workflows/release.yml`, triggered by `v*` tags: validate → build (CHANGELOG gate + 5-platform binaries) → docker (semver-tagged image, CVE scan, SBOM, SLSA provenance, Cosign sign) → deploy-gate (live Helm deploy to production + health check, auto-rollback) → publish (GitHub Release with everything attached).
- `.github/workflows/validate-test.yml` / `validate-quality.yml`, extracted from `ci.yml` as reusable workflows so `release.yml` shares the exact same test/quality gates instead of duplicating them.

### Changed
- `deploy-gate`'s health query uses `grpc_server_handled_total{status_class="5xx"}` (`platform-gincommon`'s gRPC interceptor chain), not `iam-user-profile`'s `http_requests_total` — this service has no HTTP business traffic. Requires a `KUBECONFIG_B64` secret, optional `K8S_NAMESPACE`/`PROMETHEUS_URL` vars, and a pre-provisioned `iam-authz-enrichment-secrets` Kubernetes Secret in the target namespace.
- `deploy-gate` now only runs when `vars.DEPLOY_GATE_ENABLED == 'true'` (default: skipped) — checked `iam-user-profile`'s actual current `release.yml` and confirmed it has no skip logic either; it presumably just never fails there because that secret is already configured for that repo. Blocking every release on infrastructure that doesn't exist yet was the wrong default for a brand-new service. `publish` accepts a skipped gate but not a failed one, and the GitHub Release notes get an explicit "not deployed/health-checked" line when the gate was skipped, so that's visible on the Release page itself, not just in the workflow run's logs.

### Fixed
- `hadolint`'s `DL3064` false-flagged `ENV GOPRIVATE` purely because "PRIVATE" is in the name (the value is a public Go import-path glob, not a credential) — introduced by a Dependabot bump of `hadolint-action` 3.3.0 → 3.4.0. Suppressed with `# hadolint ignore=DL3064` immediately above the instruction (hadolint's ignore directive must be the line directly before the instruction it applies to — an explanatory comment sitting between the two breaks the association).
- `extract-release-notes.sh`'s `cmd | tee file | true` pattern (copied from `iam-user-profile`) silently killed the script with SIGPIPE (exit 141) under `set -euo pipefail` — `true` doesn't read stdin, so it closes the pipe before `tee` finishes writing, and the script exits right there, before the CHANGELOG-missing check or the image-metadata append ever run. Replaced with plain `>` redirection.
- `export-image-provenance.sh` (copied from `iam-user-profile`) used `cosign download attestation` to read a BuildKit-native provenance attestation (from `provenance: mode=max` on the build step) — `cosign download attestation` targets attestations *cosign itself* creates via `cosign attest`, a different format from what `docker/build-push-action`'s `provenance`/`sbom` inputs attach, and cannot read them at all regardless of `--predicate-type` filtering or build caching. Two earlier attempts each addressed a real, separately-documented issue (buildx defaults to a `v0.2` predicate rather than `v1`; combining `cache-from`/`cache-to: type=gha` with attestations can drop them per `moby/buildkit#4501`) but neither was this bug, which is why "found no attestations" persisted unchanged through both. Rewrote the script to use `docker buildx imagetools inspect --format '{{ json .Provenance.SLSA }}'` instead, which understands BuildKit's native attestation format directly — no cosign involved for this step (cosign is still used, correctly, for image *signing* later in the same job). Left the `v0.2` predicate-type awareness and the `type=gha` cache removal in place — both are still real, worth having regardless of whether they were the culprit here.

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

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `.github/workflows/release.yml`, triggered by `v*` tags: validate → build (CHANGELOG gate + 5-platform binaries) → docker (semver-tagged image, CVE scan, SBOM, SLSA provenance, Cosign sign) → publish (GitHub Release with everything attached). Deliberately omits `iam-user-profile`'s `deploy-gate` job (a live `helm upgrade` against a production cluster) — no `KUBECONFIG_B64` secret is configured here, so a copy-pasted gate would fail every release.
- `.github/workflows/validate-test.yml` / `validate-quality.yml`, extracted from `ci.yml` as reusable workflows so `release.yml` shares the exact same test/quality gates instead of duplicating them.

### Fixed
- `hadolint`'s `DL3064` false-flagged `ENV GOPRIVATE` purely because "PRIVATE" is in the name (the value is a public Go import-path glob, not a credential) — introduced by a Dependabot bump of `hadolint-action` 3.3.0 → 3.4.0. Suppressed with `# hadolint ignore=DL3064` immediately above the instruction (hadolint's ignore directive must be the line directly before the instruction it applies to — an explanatory comment sitting between the two breaks the association).
- `extract-release-notes.sh`'s `cmd | tee file | true` pattern (copied from `iam-user-profile`) silently killed the script with SIGPIPE (exit 141) under `set -euo pipefail` — `true` doesn't read stdin, so it closes the pipe before `tee` finishes writing, and the script exits right there, before the CHANGELOG-missing check or the image-metadata append ever run. Replaced with plain `>` redirection.

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

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Initial implementation of the `iam-authz-enrichment` Envoy `ext_authz` Policy Decision Point: §3.1 precedence chain, §4 Valkey caching, §5 event consumption, §7 failure-handling matrix, §10 observability.
- Trivy CVE scan, a dedicated smoke-test job, and a GHCR image publish (SBOM + provenance attestations, Cosign keyless signing) in CI.
- `deploy/helm/` chart, `deploy/iam/` reference IAM policy, and `deploy/monitoring/` Prometheus alerting rules for platform deployment.

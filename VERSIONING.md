# Versioning and releases

This repository is a **deployed Go microservice**, not a library other services `go get` — it has no `pkg/` public API, and its `go.mod` module path exists so this repo's own code compiles, not for import by sibling repos (contrast [`platform-events`](https://github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events)'s `VERSIONING.md`, which this document is modeled on but differs from for that reason). What gets versioned here is the **container image** (`ghcr.io/bcbp-solutions-fzc-llc/iam-authz-enrichment`) and the **Helm chart** (`deploy/helm/`) that deploys it, plus the runtime contract Envoy and every downstream service depend on. Versions are published with **Git tags** and described in [CHANGELOG.md](./CHANGELOG.md).

## Semantic versioning (SemVer)

We use [SemVer 2.0.0](https://semver.org/): `MAJOR.MINOR.PATCH` (e.g. `v1.2.3`).

| Bump | When you change | Examples |
|------|-----------------|----------|
| **MAJOR** | Breaking change in the runtime contract (§ below) | Removing/renaming a `DenyReason`, changing an injected header's name or semantics, removing a `context_extensions` key a route config relies on, removing/renaming a required env var, an incompatible `values.yaml` restructure |
| **MINOR** | New backward-compatible capability | A new `DenyReason` that doesn't change existing precedence/semantics, a new optional env var, a new optional Helm value, a new consumed event type, a new Prometheus metric |
| **PATCH** | Backward-compatible fix | Bug fix, performance improvement, dependency bump with no observable behavior change, documentation-only correction |

### What counts as the runtime contract

This service has no Go package for another service to import — its "public API" is the wire/deployment contract every caller and operator depends on.

| In scope (SemVer applies) | Out of scope (may change without MAJOR) |
|---------------------------|------------------------------------------|
| `internal/domain/decision.go`'s `DenyReason` values and their HTTP-status/gRPC-code mapping (LLD §9) | `internal/*` package structure, exported Go identifiers, file layout — nothing here is imported by another module |
| The six `x-*` injected headers on `Allow` — names and semantics (LLD §5.3) | `cmd/server/main.go` internals, wiring order |
| `CheckRequest` field usage this service reads: `attributes.metadata_context[<namespace>].<payload key>` (namespace/key configurable via `JWT_METADATA_NAMESPACE`/`JWT_PAYLOAD_KEY`) and `attributes.context_extensions`'s five keys (`policy_action`, `department_id`, `required_department_level`, `assignee_user_id`, `required_access_level`), plus the `/tenders/{id}` URL-path requirement for `tender_id` (LLD §16 AE-22) | Exact log line format/fields, beyond the documented `sub`/`iss`-only redaction rule (LLD §11.4) |
| Required env var **names and semantics** (LLD §12, `.env-example`) | Env var **defaults** — tunable without a MAJOR bump unless the new default itself breaks a documented invariant (e.g. the fail-fast dev-default checks in `internal/config/config.go`) |
| `deploy/helm/values.yaml` top-level key names and shapes consumers actually set (`image.*`, `env.*`, `service.*`, `secret.existingSecret`, replica/HPA fields) | Chart internals (`_helpers.tpl`, template structure) not exposed as a `values.yaml` key |
| Prometheus metric **names** listed in LLD §11.2 (`iam_authz_enrichment_decisions_total`, `iam_authz_enrichment_decision_latency_seconds`, `iam_authz_enrichment_cache_lookups_total`/`_hits_total`, `iam_authz_enrichment_negative_cache_*`, `iam_authz_enrichment_dependency_request_seconds{dependency}`, `iam_authz_enrichment_stale_if_error_served_total`, `iam_authz_enrichment_deny_reason_total`, `iam_authz_enrichment_singleflight_coalesced_total`) — dashboards and alert rules key off these exact names | Metric **label cardinality** beyond what's documented, histogram bucket boundaries |
| `GET /healthz`/`/readyz` (HTTP) and the native `grpc.health.v1.Health` service — existence and meaning (process-startup readiness, not dependency health) | `GET /asyncapi`/`/asyncapi.yaml` content shape — documentation, not a contract this service must hold stable for a caller |

Envoy's own `envoy.service.auth.v3.Authorization/Check` proto (from `go-control-plane`) is **not** owned by this repo — its version is tracked separately in the compatibility matrix below, not by this service's own SemVer.

### Guarantees

- **Pre-`v1.0.0` (current status):** per [SemVer §4](https://semver.org/#spec-item-4), anything may change at any time while the major version is `0` — this service has not yet committed to a stable contract. The table above still indicates what's *more* disruptive than what within `v0.x` (a MINOR bump is still meant to signal "safer than a MAJOR bump would have been"), but a downstream Envoy route config or dependent service should not yet assume `v0.x` compatibility across a MINOR bump the way it could once `v1.0.0` ships.
- **MAJOR (once `v1` ships):** we avoid breaking changes to the runtime contract within `v1.x`. A breaking change ships as `v2.0.0` with migration notes in the CHANGELOG.
- **MINOR:** safe to redeploy without changing Envoy config or Helm values, unless you opt into a new capability.
- **PATCH:** drop-in image replacement; upgrade recommended for security fixes (every release is CVE-scanned, see below).

## Supported releases

| Version | Status | Image tag | Notes |
|---------|--------|-----------|-------|
| `v0.1.0` | **Current** | `ghcr.io/bcbp-solutions-fzc-llc/iam-authz-enrichment:v0.1.0` | Pre-production — no live deployment yet (CHANGELOG's `[0.1.0]` entry), so no support window has started |
| `< v0.1.0` | — | — | No tagged releases before `v0.1.0` |

This service has no formal support-window policy yet, since nothing is running in production against a tagged release. Once a `v1.0.0` ships to a real environment, this section will define how long a superseded major line receives security-only fixes (expect the same platform convention `platform-events` uses: security fixes only, for a period the platform team sets, typically ~6 months after the next major).

## Consume a release

This service is **not** consumed via `go get` — do not add this module as a dependency of another Go service. It is consumed as a **container image** deployed behind Envoy's `ext_authz` filter, via the **Helm chart** in `deploy/helm/`.

### Pull and verify the image

```bash
docker pull ghcr.io/bcbp-solutions-fzc-llc/iam-authz-enrichment:v0.1.0
```

Every tagged release is signed keylessly via Sigstore/Cosign (no long-lived key) — verify before deploying:

```bash
cosign verify \
  --certificate-identity-regexp "^https://github\.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/.github/workflows/.*@refs/tags/.*$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/bcbp-solutions-fzc-llc/iam-authz-enrichment@<digest>
```

(Untagged `main`-branch builds use a different identity regexp — see [README.md § CI](README.md#ci) — since they're signed by the `push` job on `ci.yml`, not `release.yml`.)

### Image tag scheme

`.github/workflows/release.yml`'s `docker/metadata-action` step produces, per tag push:

| Tag pattern | Produced for | Example (from `v1.2.3`) |
|-------------|--------------|--------------------------|
| `vMAJOR.MINOR.PATCH` | Every release | `v1.2.3` |
| `vMAJOR.MINOR` | Every release | `v1.2` |
| `vMAJOR` | Every release | `v1` |
| `latest` | Stable releases only (no pre-release suffix) | `latest` |

| Pin style | Use when |
|-----------|----------|
| `vMAJOR.MINOR.PATCH` | Production; exact reproducibility (recommended — also enables the digest verification `values.yaml` supports) |
| `vMAJOR.MINOR` | Accept PATCH updates automatically |
| `vMAJOR` | Accept MINOR/PATCH updates automatically — not recommended before `v1.0.0`, see the pre-`v1` guarantee note above |
| `latest` | Local/dev experiments only; never production |

### Deploy via Helm

```bash
helm upgrade iam-authz-enrichment ./deploy/helm \
  --install \
  --namespace <your-namespace> \
  --set image.tag=v0.1.0 \
  --set existingSecret=iam-authz-enrichment-secrets
```

`image.tag` (`deploy/helm/values.yaml`) defaults to the chart's own `appVersion` (`deploy/helm/Chart.yaml`) when unset — see `_helpers.tpl`'s `image` template. Chart `version`/`appVersion` are bumped manually alongside the Git tag (see the maintainer process below); they are **not** derived automatically from the tag by any workflow today.

## Maintainer release process

`.github/workflows/release.yml` automates validation, the image build/scan/sign, an optional live health-gated deploy, and GitHub Release creation. Your job is to prepare the commit and push the tag.

1. **Merge** all changes for the release to `main`.

2. **Update `CHANGELOG.md`:** move `[Unreleased]` entries into a new `## [X.Y.Z] - YYYY-MM-DD` section. `build`'s `verify-changelog-entry.sh` step fails the release if this section is missing — cut it *before* tagging.

3. **Bump `deploy/helm/Chart.yaml`'s `version`/`appVersion`** to match `X.Y.Z`. Nothing does this automatically — the release workflow overrides `image.tag` at deploy time via `--set`, but a consumer who deploys the chart without setting `image.tag` explicitly gets whatever `appVersion` was last committed, so a forgotten bump here silently ships a stale image to anyone relying on the chart's own default.

4. **Run `make ci` locally** to confirm everything is green before tagging:
   ```bash
   make ci   # tidy + fmt-check + vet + lint + arch-lint + test-ci (race, 100% coverage gate) + build
   ```

5. **Create and push an annotated tag** — this triggers the release workflow automatically:
   ```bash
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

6. **The release workflow** (triggered by the tag) runs:
   - `validate-test`/`validate-quality` — the same reusable gates `ci.yml` uses, re-run at the exact tagged commit.
   - `build` — verifies the tag matches HEAD, verifies the CHANGELOG entry exists, cross-compiles binaries for 5 platforms (a convenience for non-Docker runs — this service is deployed exclusively as a container).
   - `docker` — builds and pushes the semver-tagged image (see tag scheme above), CVE-scans it (fails the release on CRITICAL/HIGH), generates a CycloneDX SBOM and SLSA provenance, signs with Cosign.
   - `deploy-gate` (skipped unless `vars.DEPLOY_GATE_ENABLED=true` — no cluster configured yet) — live Helm deploy to production, digest verification, a 2-minute gRPC 5xx-rate health check, automatic rollback on failure.
   - `publish` — creates the GitHub Release with the CHANGELOG section as notes, plus binaries/checksums/SBOM/provenance attached; notes explicitly when `deploy-gate` was skipped so a reader knows the release wasn't verified against a live deployment.

7. **Notify consumers** — whoever owns the Envoy/gateway route config and the Helm deployment for this service (not Go importers, since there are none) — with upgrade notes if MINOR or MAJOR.

### Pre-release tags (optional)

| Tag pattern | Meaning |
|-------------|---------|
| `v1.1.0-rc.1` | Release candidate; not for production unless approved |
| `v1.1.0-beta.1` | Early integration testing |

Both match `release.yml`'s tag trigger (`v[0-9]*.[0-9]*.[0-9]*-*`) and produce a signed, scanned image — but never a `latest` tag (see the tag scheme table above).

## Compatibility matrix

| iam-authz-enrichment | Go (`go.mod`) | Envoy `ext_authz` API | `go-control-plane` |
|---|---|---|---|
| `v0.1.x` | `1.26.6+` | `V3` (`transport_api_version: V3`) | `v1.37.0` |

Key runtime dependencies pinned in `go.mod` at the time of a given release (see `CHANGELOG.md` for exact per-release bumps): `platform-gincommon` (gRPC observability interceptors, health handler), `platform-events` (SQS consumer loop, `Envelope[T]` decoding). Neither is re-exported — a consumer of this *service* never needs either as a direct dependency.

## Related files

| File | Purpose |
|------|---------|
| [CHANGELOG.md](./CHANGELOG.md) | User-facing history per version |
| [README.md](./README.md) | Mental model, interface contract, local dev, CI/CD summary |
| [CONTRIBUTING.md](./CONTRIBUTING.md#deployment) | Full deployment/release pipeline description, required secrets |
| [docs/lld/iam-lld-authz-enrichment.md](./docs/lld/iam-lld-authz-enrichment.md) | The runtime contract in full — §5 CheckRequest/CheckResponse shape, §9 `DenyReason`/status table, §11.2 metric names, §12 configuration |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Layer model, threat model, key invariants |
| [.github/workflows/release.yml](./.github/workflows/release.yml) | Automated release pipeline |
| [deploy/helm/Chart.yaml](./deploy/helm/Chart.yaml) | Helm chart version / app version |
| [go.mod](./go.mod) | Module path and minimum Go version — not a consumable package |

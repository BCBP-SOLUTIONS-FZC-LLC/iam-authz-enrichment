# Contributing

This is an internal IAM microservice for the XpertPMS platform — the Envoy `ext_authz`
Policy Decision Point. This guide covers development setup, how to extend the service,
test requirements, and the PR process.

## Prerequisites

- Go 1.26.9+ (matches `go.mod`)
- Docker (required for the Valkey + LocalStack SQS integration tier)
- `golangci-lint` and `go-arch-lint` are managed as Go tools — no separate install needed
- `GOPRIVATE=github.com/BCBP-SOLUTIONS-FZC-LLC/*` (private module access)

## Development setup

```bash
git clone https://github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment
cd iam-authz-enrichment
make setup      # copies .env-example → .env
make tidy       # go mod tidy
make docker-up  # start Valkey + LocalStack (SQS)
make lint       # verify linter passes
make test       # unit tests (no Docker required)
make run        # start the server (:8080 HTTP, :9091 gRPC)
```

To run only unit tests:

```bash
make test
```

`make setup` installs `.githooks/pre-commit`, which runs `make tidy`, `fmt-check`, and `lint`
before every commit. Re-run `make install-hooks` any time `.githooks/pre-commit` changes.

## Project layout

```
cmd/server/                    ← Composition root — wiring, graceful shutdown, gRPC/HTTP registration
internal/
  domain/                      ← Entities, value objects, DenyReason enum, domain errors (no external deps)
    policy/                    ← §3 base role/department policy as pure predicate functions
  usecase/                     ← §3.1 precedence chain, §5 invalidation, §7 failure-handling matrix
  config/                      ← Env var loading
  adapter/inbound/
    grpc/                      ← envoy.service.auth.v3.Authorization/Check server
    http/                      ← healthz/readyz only — no business HTTP API; /metrics has its own dedicated listener (cmd/server)
    consumer/                  ← one handler per §5 SQS queue
  adapter/outbound/
    valkey/                    ← Cache adapter (go-redis/v9), §4 key schema + jittered TTL envelope
    orgmembership/              ← I-8/I-14 HTTP client (Org & Membership) + TAC-4/I-12 HTTP client (iam-tender-acl, ADR-0007 Wave 3 Phase 4)
    metrics/                   ← Prometheus recorder
test/
  fixtures/                    ← Hand-written fakes for usecase ports (no gomock/mockery)
  integration/                 ← Build-tag `integration`, real Valkey + LocalStack
  load/                        ← Manual 500 RPS harness, not run in CI
```

**Dependency rule:** `domain` ← `usecase` ← `adapter` ← `cmd`. Nothing in `internal/domain`
or `internal/usecase` may import an adapter package. Enforced in CI by `go-arch-lint`
(`.go-arch-lint.yml`).

For full layout and flow details see [ARCHITECTURE.md](ARCHITECTURE.md).

## Extending the service

### Adding a new domain type

1. Add the type to `internal/domain/` (or `internal/domain/policy/`) — no external imports allowed.
2. Add a corresponding `New*` constructor if it needs invariant enforcement (e.g. empty-not-nil slices).
3. Add unit tests alongside the package (`internal/domain/*_test.go`).

### Adding or changing a §3.1 precedence step

1. Implement the check in `internal/usecase/check.go`, keeping the existing step order —
   the chain is "first failing check wins," never whichever branch happens to run first.
2. If the new step depends on Org & Membership, add the client method to
   `internal/adapter/outbound/orgmembership/client.go` and the port to `internal/usecase/ports.go`.
3. Add a precedence-order test: a request that fails this check *and* a later one must resolve
   to this step's `DenyReason`, not the later one's.
4. Update the precedence table in `ARCHITECTURE.md` and the Policy input table in `README.md`
   if the request facts / headers changed.

### Adding a new cached value

1. Add the key builder to `internal/adapter/outbound/valkey/keys.go` and the TTL to
   `internal/config/config.go` + `.env-example`.
2. Decide fresh/stale semantics deliberately — most values use the single-envelope
   fresh-read/§7-stale-if-error trick (`entry[T]{Value,FetchedAt,SoftTTL}`); a value that must
   react immediately to a tenant-side change (like `mfa_freshness_seconds`) must **never** be
   cached at all, and needs a dedicated regression test asserting no `Set*` call for it exists.
3. Update the §4 cache key table in `README.md`/`ARCHITECTURE.md`.

### Adding a new §5 event type / consumer

1. Add the queue URL env var to `.env-example` and `internal/config/config.go`.
2. Add a `Handle*` method to `internal/usecase/invalidate.go` (kept separate from SQS plumbing
   so it's unit-testable without LocalStack) and a `New*Consumer` builder in
   `internal/adapter/inbound/consumer/`.
3. Wire it in `cmd/server/main.go`, following the existing shutdown order
   (gRPC → HTTP → consumers → cancel → cache.Close).
4. Add one eviction test asserting the exact key touched and nothing else, plus update
   `scripts/init-localstack.sh` and the CI `test` job's queue list if the queue is new.
5. Update the consumed-event table in `README.md § Testing events locally` and in `ARCHITECTURE.md`.
6. If the queue is new (not a handler added to an existing queue), add its ARN to the
   `ConsumeAuthzEvents` statement in `deploy/iam/policy.json` and the Terraform
   `templatefile` call in `deploy/iam/policy.tf.example` — the IAM role must be updated
   before the new consumer is deployed, or it fails on its first `ReceiveMessage` call.
7. If the queue is new, also add its `-dlq` name to `deploy/monitoring/dlq-alarms.tf.example`'s
   `authz_dlq_names` list, and its `-dlq` ARN to `deploy/iam/policy.json`'s
   `ForwardPoisonMessagesToDLQ` statement (the consumer forwards poison messages there and refuses
   to start on a queue without a RedrivePolicy). No application code reads a `-dlq` queue, so
   without an alarm a message that lands there sits unmonitored indefinitely.

### Adding a new environment variable

1. Add it to `.env-example` with an inline comment explaining purpose, accepted values, and
   any hard invariant (e.g. "capped at 5m regardless of what this is set to").
2. Read it in `internal/config/config.go`.
3. Update the Environment variables table in `README.md`.
4. If a real deployment must set it to something functional (not just tune a default —
   compare `ORG_MEMBERSHIP_BASE_URL` vs. `AE_CTX_TTL`), consider whether `Load()` should
   fail fast when it's left at a non-functional default outside `APP_ENV=dev`, the same way
   `ORG_MEMBERSHIP_BASE_URL` does. A silent default that only breaks at request time is much
   harder to diagnose than a startup crash-loop with a clear error message.
5. If it also needs to reach `platform-gincommon` (e.g. another `OTEL_*` var), check whether
   that library reads it via `os.Getenv` directly rather than through this service's own
   config — if so, it won't inherit this service's own `APP_ENV` *default* the way this
   service's own env vars do (see `.env-example`'s `OTEL_EXPORTER_OTLP_INSECURE` comment for
   the exact gotcha this caused).

## Testing requirements

| Layer | Location | Docker | Notes |
|-------|----------|--------|-------|
| Unit | `internal/.../*_test.go` | No | Hand-written fakes (`test/fixtures`); fully isolated |
| Integration | `test/integration/` (build tag `integration`) | Yes | Real Valkey + real LocalStack SQS, incl. a DLQ test waiting for 5 real redeliveries |
| Load | `test/load/` | No (needs a running instance) | Manual 500 RPS harness; not part of CI |

All unit tests must pass without Docker (`make test`). The integration tier requires
`make docker-up` first.

Run the race detector before submitting a PR (`make ci` does this automatically via `test-ci`):

```bash
make race
```

### Coverage gate

Target is **100% statement coverage on `internal/...`**, measured via `make test-ci`
(`-race`, `-coverpkg` spanning every domain/usecase/adapter package) and enforced in CI by
`.github/scripts/coverage-gate.sh` — a PR that drops below 100% fails the `test` job.
`codecov` also receives `coverage.out` for trend visibility.

Two things worth knowing before you chase the last few tenths of a percent:
- **`NoopRecorder`'s empty-bodied methods** (`internal/usecase/ports.go`) always show `0.0%`
  individually, no matter how many tests call them — Go's coverage tool can't instrument a
  function with zero statements. They contribute 0/0 and don't drag down the total; don't
  add dummy statements to "fix" this.
- **Don't add a `default:`-avoiding, per-value `switch` case just to defensively fail closed
  on values that can't occur at that call site** (see the fix to `resolveContext`'s outcome
  switch in `internal/usecase/check.go` for the pattern) — it produces an unreachable trailing
  statement Go's compiler forces you to write, which never reaches 100%. Use `default:` instead
  (same fail-closed defensive behavior, reachable, and add `//nolint:exhaustive` with a comment
  explaining which values are actually possible there — don't loosen the `exhaustive` linter
  setting repo-wide for one switch).

```bash
make cover-func   # per-function summary in terminal
make cover        # HTML report
```

## Linting

```bash
make lint       # golangci-lint
make arch-lint  # .go-arch-lint.yml component-boundary check
```

`.golangci.yml` enforces `unparam`, `revive`, and other rules — this is where the
`decodeClaims`/`authTimeField` naming (see `internal/adapter/inbound/grpc/claims.go`) came
from after an `unparam` finding.

## Documentation update checklist

When your change touches a public contract or internal data flow, update the following:

| What changed | Documents to update |
|---|---|
| §3.1 precedence step added/reordered | README.md Policy input table · ARCHITECTURE.md precedence table + `docs/architecture/mermaid/request-flow.mmd` |
| §4 cache key or TTL | README.md Environment variables table · ARCHITECTURE.md cache-strategy section + `.mmd` source |
| §5 event type / queue | README.md event table · ARCHITECTURE.md event-flow section + `.mmd` source · `scripts/init-localstack.sh` · CI `test` job service list |
| New environment variable | `.env-example` (inline comment) · README.md Environment variables table |
| §7 failure-handling row | ARCHITECTURE.md failure-domains table + `.mmd` source |
| New or renamed package | ARCHITECTURE.md layer model + `docs/architecture/mermaid/layer-model.mmd` · `.go-arch-lint.yml` |

## Branch naming

Feature branches follow one of these forms:

- `feat/<short-topic>` — new capability
- `fix/<short-topic>` — bug fix
- `docs/<short-topic>` — documentation-only change
- `chore/<short-topic>` — dependencies, tooling, CI, refactors with no behavioural change

Base new branches off the latest `main`. This service has no `develop` or other
long-running integration branch — target `main` unless a maintainer says otherwise.

## Pull request checklist

- [ ] `make ci` passes locally — runs `tidy` + `fmt-check` + `vet` + `lint` + `arch-lint` + `test-ci` (`-race` + coverage) + `build`, mirroring CI exactly
- [ ] **`make race` passes with zero data races detected**
- [ ] New exported symbols have godoc comments
- [ ] New behaviour is covered by tests in the appropriate layer (`internal/.../*_test.go` or `test/integration/`)
- [ ] Documentation update checklist above reviewed — relevant docs updated
- [ ] No new source of identity/authz input other than Envoy's validated `Attributes.MetadataContext` (§8) — never a request header
- [ ] If a cached value was added: confirmed it's *not* `mfa_freshness_seconds` or an equivalent "must react immediately" value, or explicitly excluded from caching with a regression test
- [ ] If a new effectively-required env var was added (something every real deployment must set, not just tune): confirmed whether it needs a fail-fast check in `internal/config/config.go` like `ORG_MEMBERSHIP_BASE_URL`'s, rather than silently defaulting to a non-functional dev value in production

## Commit style

Use a short imperative subject line (≤ 72 chars). Reference the area:

```
fix(usecase): evict processed marker on handler failure so retries aren't swallowed
feat(consumer): add TenantRealmReady handler for direct-paid-signup realm refresh
docs: document grpcui walkthrough for the tender-ACL overlay
test(failure): add stale-if-error 5-minute boundary case
chore(deps): bump platform-events to v1.4.0
```

## Deployment

This service is deployed as a containerised microservice behind Envoy as its `ext_authz`
sidecar/filter target. On push to `main` or on a pull request, `.github/workflows/ci.yml` runs
`test` (race + coverage gate at 100%, unit + integration against real Valkey/LocalStack service
containers), `quality` (`fmt-check`/`vet`/`lint`/`arch-lint`/`mod-verify`/`vuln-check`), and
`build-image` (Hadolint + Docker build-to-cache) in parallel, then `trivy` (CVE scan + SBOM)
and `smoke` (liveness check against the built image) once `build-image` finishes.
`changelog-check.yml` additionally requires a `CHANGELOG.md` `[Unreleased]` entry on any PR
touching `internal/` or `cmd/`. A `pr-summary` job posts a single status comment on pull
requests once those jobs finish.

On push to `main`/`master` specifically, a `push` job builds and publishes the image to
`ghcr.io/bcbp-solutions-fzc-llc/iam-authz-enrichment` (tagged by branch and short SHA, with
SBOM + provenance attestations), then signs it with Cosign using keyless Sigstore OIDC
signing — no long-lived signing key to rotate or leak, no secret beyond the default
`GITHUB_TOKEN`. This requires repo Settings → Actions → Workflow permissions set to "Read and
write"; without it, the GHCR login/push step fails.

Pushing a `v*` tag (e.g. `v0.1.0`, `v1.0.0-rc.1`) triggers `.github/workflows/release.yml`:
`validate-test`/`validate-quality` (the same reusable gates `ci.yml` uses) → `build` (verifies
the tag matches HEAD, verifies `CHANGELOG.md` has a matching `## [x.y.z]` entry, cross-compiles
binaries for 5 platforms) → `docker` (builds, pushes a semver-tagged image, CVE-scans it,
generates an SBOM + SLSA provenance, signs with Cosign) → `deploy-gate` (live Helm deploy to
production + health check, with automatic rollback) → `publish` (creates the GitHub Release with
the CHANGELOG section as notes, plus the binaries/checksums/SBOM/provenance attached).
Cut the `CHANGELOG.md` entry *before* tagging — `build` fails the release otherwise.

`deploy-gate` is **skipped by default** — it only runs when the `vars.DEPLOY_GATE_ENABLED`
repository/environment variable is `true`. `secrets` can't be read in a job-level `if:`
(a GitHub Actions restriction), which is why this is a `vars` toggle rather than checking
`KUBECONFIG_B64` directly; `publish` treats a skipped gate as acceptable but a *failed* one
(it ran and something tripped) as blocking, and the eventual GitHub Release notes get an
explicit "not deployed/health-checked" note when the gate was skipped, so that's visible on
the Release page itself, not just in the workflow run's logs. Set `DEPLOY_GATE_ENABLED=true`
once there's a real cluster, a `KUBECONFIG_B64` secret (the job's own first step fails clearly
if that's missing — a real safety net for the case where the toggle was flipped on before the
secret was set), optional `K8S_NAMESPACE`/`PROMETHEUS_URL` vars, and a pre-provisioned
Kubernetes Secret named `iam-authz-enrichment-secrets` in the target namespace (the chart's
`secret.yaml` hard-fails the Helm render via `existingSecret` otherwise). Its health query uses
`platform_grpc_server_handled_total{domain="iam",service="iam-authz-enrichment",status_class="5xx"}`
(from `platform-gincommon`'s gRPC interceptor chain; registry status *proposed*) rather than
`iam-user-profile`'s `platform_http_requests_total` — this service has no HTTP
business traffic, and `status_class="5xx"` only fires on a genuine transport-level RPC failure
(`internal/adapter/inbound/grpc/server.go`'s `Check()` always returns a nil error for every
Allow/Deny outcome), so it's a clean deployment-health signal distinct from
`iam_authz_enrichment_deny_reason_total{reason="deny_service_unavailable"}` (dependency health, not deployment
health — an unrelated dependency outage at deploy time shouldn't trigger a rollback).

Notify the platform team on Slack if a change here affects the Envoy `ext_authz` contract
(response headers, `DenyReason` set, or the `CheckRequest` fields it reads) — every service
behind this filter is a downstream consumer.

The Helm chart in `deploy/helm/` (applied by the platform CD pipeline) has no
Ingress/HTTPRoute template — Envoy reaches `Authorization.Check` directly via the chart's
`grpc` Service port by cluster DNS, not through a Route resource. See `deploy/iam/README.md`
for the IRSA role/policy this service's ServiceAccount needs, and `deploy/monitoring/` for
the Prometheus alerting rules (thresholds match the SLOs in `ARCHITECTURE.md` §10) and the
optional prometheus-adapter config for decision-rate HPA scaling.

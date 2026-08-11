# Contributing

This is an internal IAM microservice for the XpertPMS platform — the Envoy `ext_authz`
Policy Decision Point. This guide covers development setup, how to extend the service,
test requirements, and the PR process.

## Prerequisites

- Go 1.26.5+ (matches `go.mod`)
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
    http/                      ← healthz/readyz/metrics only — no business HTTP API
    consumer/                  ← one handler per §5 SQS queue
  adapter/outbound/
    valkey/                    ← Cache adapter (go-redis/v9), §4 key schema + jittered TTL envelope
    orgmembership/              ← I-8/I-12/I-14 HTTP client
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

### Adding a new environment variable

1. Add it to `.env-example` with an inline comment explaining purpose, accepted values, and
   any hard invariant (e.g. "capped at 5m regardless of what this is set to").
2. Read it in `internal/config/config.go`.
3. Update the Environment variables table in `README.md`.

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

Target is **≥ 97% statement coverage on `internal/...`**, measured via `make test-ci`
(`-race`, `-coverpkg` spanning every domain/usecase/adapter package) and enforced in CI by
`.github/scripts/coverage-gate.sh` — a PR that drops below 97% fails the `test` job.
`codecov` also receives `coverage.out` for trend visibility.

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
sidecar/filter target. On push to `main` or on a pull request, `.github/workflows/ci.yml`
runs three jobs in parallel: `test` (race + coverage gate ≥97%, unit + integration against
real Valkey/LocalStack service containers), `quality` (`fmt-check`/`vet`/`lint`/`arch-lint`/
`mod-verify`/`vuln-check`), and `build-image` (Hadolint + Docker build-only, no push, plus a
liveness smoke test against the built image). `changelog-check.yml` additionally requires a
`CHANGELOG.md` `[Unreleased]` entry on any PR touching `internal/` or `cmd/`. A `pr-summary`
job posts a single status comment on pull requests once the three CI jobs finish.

There is currently no tag-triggered release workflow, image push, or signing step in this
repo (unlike `iam-user-profile`'s `release.yml`) — add one deliberately, matching the
platform team's actual deployment target, rather than copying that pipeline wholesale.
Notify the platform team on Slack if a change here affects the Envoy `ext_authz` contract
(response headers, `DenyReason` set, or the `CheckRequest` fields it reads) — every service
behind this filter is a downstream consumer.

# iam-authz-enrichment

Real-time authorization decisions for the platform: enriches every authenticated request with tenant, role, and permission context via a low-latency, cache-backed policy engine.

**Repository:** `github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment`
**Module:** Go 1.26.5+ · private module · stateless, 5–20 replicas, HPA on RPS · **no database**

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full layer model, request-flow/cache/event/failure-handling diagrams, and the threat model.

---

## Mental model

This service is the platform's **Policy Decision Point**. Envoy is the **Policy Enforcement Point**.

| Layer | What it owns | What it does NOT own |
|-------|-------------|----------------------|
| **Identity input** | Reading `sub`/`iss`/`tenant_id`/`auth_time` from Envoy's already-validated JWT metadata | JWT signature/`iss`/`aud`/`exp` validation — exclusively `jwt_authn`'s job |
| **Tenant resolution** | `iss` → dedicated realm (in-process map) or `tenant_id` claim → shared trial realm | Realm/tenant provisioning, the Keycloak Admin API — never called directly |
| **Policy decision** | Allow/Deny + typed `DenyReason`, evaluated via the fixed §3.1 precedence chain | Policy *authoring* — policies are Go code, compiled in, redeployed to change; no Rego/OPA, no UI |
| **Context enrichment** | The 6 trust-boundary headers (`x-tenant-id`, `x-user-id`, `x-departments`, `x-tenant-roles`, `x-plan`, `x-feature-flags`) injected on Allow | User profile data, MFA enrollment — owned by Org & Membership / User Profile |
| **Caching** | A Valkey-backed read-through cache in front of Org & Membership, with its own TTL/jitter/stale-if-error rules | The source of truth — Org & Membership's own cache/DB is authoritative; this service only bounds staleness |
| **Event consumption** | 5 SQS queues that keep the cache honest | Publishing — this service emits nothing to the bus |

**Source of truth for one platform-wide contract:** the six injected headers. Every downstream service trusts them implicitly over the mTLS-enforced mesh — there is no other authorization layer between Envoy and a destination service.

---

## Why this service exists

Every downstream service needs to know *who* is calling and *what* they're allowed to do, on every request, in single-digit milliseconds. Without a dedicated enrichment layer, that logic would either live duplicated in every service (divergent, unauditable) or require a synchronous call to Org & Membership on every single request (an availability and latency dependency for the entire platform on every hop).

This service **centralizes** the decision and the caching:
- One place implements the precedence order (§3.1) — no service-specific reimplementation drift.
- One cache absorbs the read load Org & Membership would otherwise see on every authenticated request platform-wide.
- One place owns the failure-handling posture (§7) — bypass, stale-if-error, fail-closed — so every downstream service gets the same degraded-mode behavior for free instead of each inventing its own.

---

## Interface

There is no REST API. The only inbound interface is Envoy's `ext_authz` v3 gRPC contract.

### `Authorization.Check`

Envoy calls `Check(CheckRequest) → CheckResponse` after `jwt_authn` has validated the JWT and before forwarding to the destination service.

**Identity input** (read from `CheckRequest.Attributes.MetadataContext`, configured via `JWT_METADATA_NAMESPACE`/`JWT_PAYLOAD_KEY` — see [claims.go](internal/adapter/inbound/grpc/claims.go)):

| Claim | Used for |
|-------|----------|
| `sub` | Subject / user ID |
| `iss` | Realm → tenant resolution |
| `tenant_id` | Shared trial-realm tenant resolution (dedicated realms resolve via `iss` instead) |
| `auth_time` | MFA-freshness comparison (approver-gated actions only) |

**Policy input** (read from `CheckRequest.Attributes.ContextExtensions`, set per-route in Envoy's HTTP filter config — the standard `ext_authz` mechanism for attaching static route metadata the raw request doesn't otherwise carry):

| Key | Purpose |
|-----|---------|
| `policy_action` | One of `edit_tender_section`, `override_workflow_assignee`, `manage_department_memberships`, or unset (no base-policy restriction) |
| `assignee_user_id` | Current ticket assignee, for the edit-tender-section policy |
| `department_id` | Acting department, for department-level checks |
| `required_department_level` | `preparator`/`reviewer`/`approver` — `approver` triggers the MFA-freshness gate |
| `tender_id` / `required_access_level` | Tender-scoped actions — triggers the tender-ACL overlay if the tender is flagged restricted |

**On Allow**, `OkHttpResponse.Headers` carries exactly six headers, nothing else — see [decision.go](internal/domain/decision.go):

```
x-tenant-id  x-user-id  x-departments  x-tenant-roles  x-plan  x-feature-flags
```

`x-departments` is `department_id:level` pairs, comma-joined. `x-tenant-roles` and `x-feature-flags` are comma-joined lists.

**On Deny**, `DeniedHttpResponse` carries a `DenyReason` (see [`ARCHITECTURE.md` §Request flow](ARCHITECTURE.md#request-flow) for the full precedence table) as both the gRPC status message and the HTTP body, mapped to 401/403/503.

### Envoy configuration sketch

```yaml
# jwt_authn — validates the JWT and writes verified claims to dynamic metadata
# (payload_in_metadata is what claims.go's JWT_PAYLOAD_KEY must match)
http_filters:
  - name: envoy.filters.http.jwt_authn
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
      providers:
        trial:
          payload_in_metadata: trial
          # ... issuer, jwks, forward, etc.

  # ext_authz — calls this service, forwarding the jwt_authn metadata namespace
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      transport_api_version: V3
      metadata_context_namespaces: ["envoy.filters.http.jwt_authn"]
      grpc_service:
        envoy_grpc:
          cluster_name: iam-authz-enrichment
        timeout: 0.02s   # single-digit ms of headroom inside the 15ms p99 budget

# Per-route context_extensions attach the policy_action / department_id / etc.
# facts a raw request doesn't otherwise carry (see the Policy input table above).
```

---

## Architecture

Clean Architecture — dependencies point inward; outer layers never import inner layers.

```
iam-authz-enrichment/
├── cmd/server/                        # Composition root: config, logger, cache, org client, gRPC+HTTP servers, 5 SQS consumers
├── internal/
│   ├── domain/                        # Decision, DenyReason, MembershipContext, TenantContext, TenderACL, sentinel errors
│   │   └── policy/                    # Pure predicate functions — EvaluateBase, ViolatesReadOnly, MeetsDepartmentLevel (§3, no I/O)
│   ├── usecase/                       # Checker (§3.1 chain), Invalidator (§5), DecideDependencyOutcome (§7), RealmMap, RestrictedTenderSet
│   ├── adapter/
│   │   ├── inbound/
│   │   │   ├── grpc/                  # ext_authz v3 server — claims/request-facts decode, response encode
│   │   │   ├── http/                  # /healthz · /readyz · /metrics only — no business logic
│   │   │   └── consumer/              # 5 SQS consumers, one per §5 queue
│   │   └── outbound/
│   │       ├── valkey/                # Cache — ae:ctx · ae:tenant · ae:tender_acl · ae:neg · ae:processed
│   │       ├── orgmembership/         # HTTP client — I-8 memberships, I-12 tender-acl, I-14 mfa-freshness
│   │       └── metrics/               # Prometheus authz_* series (§10)
│   └── config/                        # Load() — env vars only, no hot-reload (§11)
├── docs/architecture/                 # Mermaid diagram sources — see ARCHITECTURE.md
├── scripts/init-localstack.sh         # Creates the 5 queues + their -dlq, with the maxReceiveCount=5 redrive policy
└── test/
    ├── integration/                   # Real Valkey + LocalStack SQS (build tag `integration`)
    ├── load/                          # Manual 500 RPS / cache-miss harness — not run in CI
    └── fixtures/                      # Hand-written fakes (FakeCache, FakeOrgMembershipClient) — no gomock/mockery
```

Unit tests are co-located with their source (`*_test.go` next to the file under test) — 99%+ statement coverage using `miniredis` for real Valkey wire-protocol tests and a fake SQS client for consumer lifecycle tests, neither requiring Docker.

### Dependency rules (enforced by `go-arch-lint` in CI)

| Package | May import |
|---------|-----------|
| `domain` | Nothing outside itself |
| `domain/policy` | `domain` only |
| `config` | Nothing internal — pure env-var loading |
| `usecase` | `domain` + `domain/policy` (never a concrete adapter — adapters satisfy `usecase/ports.go` structurally) |
| `adapter/inbound/*` | `usecase` + `domain` + `domain/policy` |
| `adapter/outbound/*` | `domain` + `domain/policy` only — **never** `usecase` |

### Storage and messaging

| Concern | Technology | Notes |
|---------|-----------|-------|
| **Cache** | Valkey (`go-redis/v9`) | The only persistent-ish state this service touches — no database, no ORM, no migrations |
| **Sibling service** | Org & Membership (HTTP, mTLS) | I-8 membership rebuild, I-12 tender-ACL, I-14 MFA-freshness — the source of truth behind the cache |
| **Events (consumed)** | AWS SQS, 5 queues | `platform-events` consumer; DLQ via SQS's own `maxReceiveCount=5` redrive policy, no application code |
| **Events (published)** | None | This service emits nothing to the bus |

### Shared library dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| `platform-gincommon` | v1.2.1 | zap logger, gRPC observability interceptors (panic-recovery/request-id/tracing/metrics/logging), health handler |
| `platform-events` | v1.4.0 | SQS consumer loop, `Envelope[T]` decoding |

---

## Local development

### Prerequisites

- Go 1.26.5+
- Docker (for `make docker-up` — Valkey + LocalStack SQS)
- SSH key or `GO_PRIVATE_TOKEN` registered for `github.com/BCBP-SOLUTIONS-FZC-LLC` (for `platform-gincommon`/`platform-events`)

### Setup

```sh
make setup       # copy .env-example to .env
make docker-up   # start Valkey + LocalStack (SQS) — scripts/init-localstack.sh creates the 5 queues + DLQs
make run         # go run ./cmd/server
```

`/healthz`, `/readyz`, `/metrics` are served on `APP_PORT` (default `8080`); the `ext_authz` gRPC service listens on `GRPC_PORT` (default `9091`).

### Common commands

Run `make help` for the full list.

```sh
make build            # compile bin/iam-authz-enrichment
make test             # unit tests — fakes only, no Docker required
make test-integration # real Valkey + LocalStack SQS (requires make docker-up first)
make lint              # golangci-lint
make arch-lint          # enforce .go-arch-lint.yml component boundaries
make cover              # coverage profile + open HTML report
make ci                 # the full local gate: tidy + fmt-check + vet + lint + arch-lint + test-ci + build
```

### Exercising the gRPC API locally

There's no REST API, so there's no Swagger UI — the direct analogs for a gRPC-only service are **`grpcurl`** (curl-equivalent) and **`grpcui`** (a literal Swagger-UI-style browser form), both driven by gRPC server reflection. Reflection is registered whenever `APP_ENV != production` (same non-prod-only convention `iam-user-profile` uses for its Swagger/AsyncAPI viewers) — see `cmd/server/main.go`.

```sh
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest
make run   # in one terminal
```

`go install` puts both binaries in `$(go env GOPATH)/bin` (typically `~/go/bin`) — if your shell reports `command not found: grpcurl`/`grpcui` afterwards, that directory isn't on your `PATH` yet. Fix it in whichever terminal you're running them from:

```sh
export PATH="$PATH:$(go env GOPATH)/bin"          # this terminal session only
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc   # permanent — open a new terminal (or `source ~/.zshrc`) to pick it up
```

**`grpcurl`** — list the service, describe a message, then call `Check`:

```sh
grpcurl -plaintext localhost:9091 list
grpcurl -plaintext localhost:9091 describe envoy.service.auth.v3.Authorization

grpcurl -plaintext -d '{
  "attributes": {
    "metadata_context": {
      "filter_metadata": {
        "envoy.filters.http.jwt_authn": {
          "trial": { "sub": "alice", "iss": "https://kc.example.com/realms/shared-trial", "tenant_id": "tenant-acme" }
        }
      }
    },
    "request": { "http": { "method": "GET", "path": "/api/v1/tenders" } }
  }
}' localhost:9091 envoy.service.auth.v3.Authorization/Check
```

`filter_metadata["envoy.filters.http.jwt_authn"]["trial"]` is exactly where Envoy's `jwt_authn` filter writes verified JWT claims (`payload_in_metadata`, see the [Envoy configuration sketch](#envoy-configuration-sketch) above) — this service reads identity *only* from there, never from headers (§8.2). With `SHARED_REALM_ISSUER` set to that `iss` value, tenant resolution falls back to the `tenant_id` claim. Without a live Valkey/Org & Membership behind it, the call above returns `DENY_SERVICE_UNAVAILABLE` (§7 fail-closed) — correct failure-handling behavior, not a broken test.

#### Seeing an `Allow` decision (mock Org & Membership)

To get past `DENY_SERVICE_UNAVAILABLE` to a real `Allow`, `GetMemberships` needs to succeed — there's no real Org & Membership service in this repo, so the fastest stand-in is a **static file server**. `python3 -m http.server` strips the query string before mapping a request to a file, so a single JSON file at the right *path* satisfies I-8 regardless of the `?tenant_id=...` query string the real client appends:

```sh
mkdir -p mockorg/api/v1/internal/users/alice
cat > mockorg/api/v1/internal/users/alice/memberships <<'EOF'
{
  "roles": ["tenant_admin"],
  "departments": [{"department_id": "fd72f513-45f0-46ca-a1ed-9183be72484c", "level": "reviewer"}],
  "active_delegations": [],
  "plan": "pro",
  "feature_flags": ["flag-a"],
  "subscription_status": "active",
  "read_only": false,
  "mfa_freshness_seconds": 300
}
EOF
(cd mockorg && python3 -m http.server 8081) &

# restart the service pointed at the mock (default 10ms ORG_MEMBERSHIP_TIMEOUT
# is too tight for Python's dev server — give it real headroom)
ORG_MEMBERSHIP_BASE_URL=http://localhost:8081 ORG_MEMBERSHIP_TIMEOUT=2s make run
```

Re-running the same `grpcurl`/`grpcui` `Check` call from above (`sub: "alice"`, `tenant_id: "tenant-acme"`) now returns `okResponse` with all six headers (`x-tenant-id: tenant-acme`, `x-user-id: alice`, `x-departments: fd72f513-45f0-46ca-a1ed-9183be72484c:reviewer`, `x-tenant-roles: tenant_admin`, `x-plan: pro`, `x-feature-flags: flag-a`) instead of a denial. `department_id` is a UUID here to match the real Org & Membership schema (`departments.id`) — this service passes whatever string the sibling sends straight through as `<department_id>:<level>` (`internal/usecase/check.go`'s `buildHeaders`) without interpreting its format, so the mock could use any string, but a UUID is what production actually looks like.

From there, edit the JSON file (or the request) to exercise other branches of §3.1 without touching any code:
- A `sub` with no matching file → 404 → `DENY_UNRESOLVABLE_SUBJECT`.
- `"read_only": true` in the mock file + `"method": "POST"` in the request → `DENY_TENANT_READ_ONLY`.
- Add `"context_extensions": {"policy_action": "manage_department_memberships"}` under `attributes` with a mock user that has no `tenant_admin`/`tenant_owner` role → `DENY_ROLE_INSUFFICIENT`.

`mockorg/` is a throwaway local directory — already covered by `.gitignore` (`mockorg*`), never commit it.

#### Testing the tender-ACL overlay (§3.1 step 4)

This overlay only runs when a request is tender-scoped *and* the tender has been flagged restricted via a real `TenderRestricted` event (§5) — there's no direct way to flip it, by design (§2: this service never invents policy state, it only reacts to events). Add the I-12 mock, then walk through all three states.

```sh
mkdir -p mockorg/api/v1/internal/tenants/tenant-acme/tenders/tender-1/acl
cat > mockorg/api/v1/internal/tenants/tenant-acme/tenders/tender-1/acl/alice <<'EOF'
{"has_access": true, "access_level": "approve", "expires_at": "2026-08-12T00:00:00Z"}
EOF
```

**1. Not flagged restricted yet** — the overlay is skipped entirely (default department membership is enough), even with `tender_id`/`required_access_level` set on the request:

```sh
grpcurl -plaintext -d '{
  "attributes": {
    "metadata_context": { "filter_metadata": { "envoy.filters.http.jwt_authn": { "trial": {
      "sub": "alice", "iss": "https://kc.example.com/realms/shared-trial", "tenant_id": "tenant-acme"
    }}}},
    "request": { "http": { "method": "GET", "path": "/api/v1/tenders/tender-1" } },
    "context_extensions": { "tender_id": "tender-1", "required_access_level": "view" }
  }
}' localhost:9091 envoy.service.auth.v3.Authorization/Check
```
→ `okResponse` (Allow).

**2. Flag it restricted**, then re-run the exact same `Check` call — now it actually calls I-12, gets `access_level: "approve"` (satisfies the required `"view"`), and still allows:

```sh
EVENT_ID=$(uuidgen 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())')
docker compose exec localstack awslocal sqs send-message \
  --queue-url http://localhost:4566/000000000000/tender-authz-q \
  --region ap-south-1 \
  --message-body "{
    \"id\": \"$EVENT_ID\", \"type\": \"TenderRestricted\", \"tenant_id\": \"tenant-acme\",
    \"time\": \"2026-08-12T00:00:00Z\", \"data\": {\"tender_id\": \"tender-1\"}
  }"
sleep 2   # let the consumer pick it up before re-running Check
```

**3. Flip the mock to an insufficient grant** and re-run `Check` a third time — now `DENY_TENDER_ACL_INSUFFICIENT`:

```sh
cat > mockorg/api/v1/internal/tenants/tenant-acme/tenders/tender-1/acl/alice <<'EOF'
{"has_access": false, "access_level": "", "expires_at": "2026-08-12T00:00:00Z"}
EOF
```

Note `ae:tender_acl:*` caches for 15s (§4.1) — if you flip the mock and re-run within that window against an *already-cached* grant, you'll still see the old cached result. Wait a beat, or just don't worry about it: real I-12 answers never 404 or flap this fast in production.

#### Testing the MFA-freshness gate (§3.1 step 5)

Add the I-14 mock (a 300s freshness window):

```sh
cat > mockorg/api/v1/internal/tenants/tenant-acme/mfa-freshness <<'EOF'
{"mfa_freshness_seconds": 300}
EOF
```

Set `required_department_level: "approver"` on the request, and vary `auth_time` in the claims — this call is **never cached** (§4.4), so every request re-evaluates it live:

```sh
# Fresh — auth_time = now → Allow
NOW=$(date -u +%s)
grpcurl -plaintext -d "{
  \"attributes\": {
    \"metadata_context\": { \"filter_metadata\": { \"envoy.filters.http.jwt_authn\": { \"trial\": {
      \"sub\": \"alice\", \"iss\": \"https://kc.example.com/realms/shared-trial\", \"tenant_id\": \"tenant-acme\", \"auth_time\": $NOW
    }}}},
    \"request\": { \"http\": { \"method\": \"POST\", \"path\": \"/api/v1/approve\" } },
    \"context_extensions\": { \"required_department_level\": \"approver\" }
  }
}" localhost:9091 envoy.service.auth.v3.Authorization/Check

# Stale — auth_time = 10 minutes ago → DENY_MFA_STALE
STALE=$(( $(date -u +%s) - 600 ))
grpcurl -plaintext -d "{
  \"attributes\": {
    \"metadata_context\": { \"filter_metadata\": { \"envoy.filters.http.jwt_authn\": { \"trial\": {
      \"sub\": \"alice\", \"iss\": \"https://kc.example.com/realms/shared-trial\", \"tenant_id\": \"tenant-acme\", \"auth_time\": $STALE
    }}}},
    \"request\": { \"http\": { \"method\": \"POST\", \"path\": \"/api/v1/approve\" } },
    \"context_extensions\": { \"required_department_level\": \"approver\" }
  }
}" localhost:9091 envoy.service.auth.v3.Authorization/Check
```

Leave `required_department_level` unset on a request and this gate — and the live I-14 call — never runs at all (verified: only the minority of approver-gated requests pay this cost, §4.4).

**`grpcui`** — same thing as a browser form:

```sh
grpcui -plaintext localhost:9091
```

Opens `http://127.0.0.1:<port>/`. Use the **"Raw Request"** tab (not "Request Form") and paste the same JSON as above — `Check`'s `attributes` field nests `AttributeContext → Metadata → Struct → Value` several layers deep, which is painful to fill in one field-checkbox at a time through the guided form but trivial as raw JSON. Click **Invoke**, then check the **Response** tab.

**Scripted / load testing:** `test/load/main.go`'s `buildCheckRequest` constructs the same shape of `CheckRequest` in Go — useful as a starting point for wiring up more scenarios, or for actually sustaining RPS:

```sh
go run ./test/load -addr=localhost:9091 -rps=5 -duration=5s -mode=hit \
  -issuer=https://kc.example.com/realms/shared-trial
```

### Testing events locally

The five SQS queues are created automatically by `docker compose up` (via `scripts/init-localstack.sh`, mounted as a LocalStack ready-hook). To drive one manually you need an AWS CLI — either your own, or the `awslocal` wrapper already baked into the LocalStack container (no local install required):

```sh
# Option A: your own AWS CLI (brew install awscli), pointed at LocalStack
aws --endpoint-url=http://localhost:4566 sqs list-queues --region ap-south-1

# Option B: no install — run it through the container instead
docker compose exec localstack awslocal sqs list-queues --region ap-south-1
```

Every command below works with either CLI — swap `aws --endpoint-url=http://localhost:4566` for `docker compose exec localstack awslocal` if you're using Option B:

```sh
# 1. Start infrastructure
make docker-up

# 2. Verify the queues exist
docker compose exec localstack awslocal sqs list-queues --region ap-south-1

# 3. Start the service (separate terminal)
make run

# 4. Send an event — e.g. a DepartmentMembershipGranted. Use a FRESH "id"
#    every time you run this: MarkProcessed (§5's idempotency guard) marks
#    each event ID processed for 7 days, so resending the same literal "id"
#    is correctly treated as a duplicate — the handler is skipped and
#    nothing gets evicted. That's the dedup contract working, not a bug.
EVENT_ID=$(uuidgen 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())')
docker compose exec localstack awslocal sqs send-message \
  --queue-url http://localhost:4566/000000000000/membership-authz-q \
  --region ap-south-1 \
  --message-body "{
    \"id\": \"$EVENT_ID\", \"type\": \"DepartmentMembershipGranted\", \"tenant_id\": \"tenant-acme\",
    \"time\": \"2026-01-01T00:00:00Z\", \"data\": {\"user_id\": \"alice\"}
  }"

# 5. Confirm the eviction happened. SQS delivery isn't instantaneous — the
#    consumer's next long-poll ReceiveMessage cycle needs to run before the
#    key disappears, so give it a moment (usually well under a second, but
#    don't expect it to be gone in the same instant send-message returns):
for i in $(seq 1 10); do
  out=$(docker compose exec valkey valkey-cli GET ae:ctx:tenant-acme:alice)
  [ -z "$out" ] && { echo "evicted"; break; }
  sleep 1
done

# The next Check() for (tenant-acme, alice) will then miss ae:ctx and rebuild
# from Org & Membership instead of serving the evicted (now-stale) entry.
```

See [`ARCHITECTURE.md` §Event flow](ARCHITECTURE.md#event-flow) for the full consumed-event-type table and the dedup/DLQ contract.

---

## Testing

- **Unit** (`internal/.../*_test.go`) — hand-written fakes (`test/fixtures`), no gomock/mockery, no Docker. Includes the §12 acceptance checklist: contract tests, one eviction test per event type, tenant-resolution edge cases, one test per §7 failure-matrix row, the `mfa_freshness_seconds`-never-cached regression, the header-spoofing regression, precedence-order tests, and the convergence-without-events vs. stale-if-error distinction test.
- **Integration** (`test/integration`, build tag `integration`) — real Valkey (via `miniredis` is unit-only; this tier uses the actual `docker-compose` Valkey) + real LocalStack SQS, including an end-to-end DLQ test that waits for 5 real redeliveries.
- **Load** (`test/load`) — manual 500 RPS / 100%-cache-miss harness against a running instance. Not run in CI; meaningful p99 numbers require a live Org & Membership instance behind `ORG_MEMBERSHIP_BASE_URL`.

```sh
make test              # unit
make docker-up && make test-integration
make load-test         # manual — see test/load
```

Coverage target: ≥97% statements on `internal/...`, enforced via `make test-ci` (`-race`, `-coverpkg` spanning every adapter/usecase/domain package).

---

## Environment variables

See [`.env-example`](.env-example) for the full annotated list. Key ones:

| Variable | Default | Notes |
|----------|---------|-------|
| `APP_PORT` / `GRPC_PORT` | `8080` / `9091` | HTTP (health/metrics) and gRPC (`ext_authz`) listen ports |
| `VALKEY_URL` | `localhost:6379` | `rediss://` for TLS in-transit in prod/staging |
| `AE_CTX_TTL` / `AE_CTX_JITTER` | `60s` / `6s` | §4.1 — desyncs expiry across replicas |
| `AE_TENDER_ACL_TTL` / `AE_NEG_TTL` | `15s` / `5s` | Half the sibling's own TTL / negative-cache storm collapse |
| `AE_STALE_IF_ERROR_MAX_AGE` | `5m` | Hard-capped at 5m regardless of configured value (§7) |
| `ORG_MEMBERSHIP_BASE_URL` / `_TIMEOUT` | `http://localhost:8081` / `10ms` | Aggressive timeout — headroom inside the 15ms p99 budget |
| `SHARED_REALM_ISSUER` | _(empty)_ | Keycloak issuer for the shared trial realm |
| `REALM_TENANT_MAP_SEED` | `{}` | Startup-only JSON seed for dedicated realms; kept fresh at runtime by events, never re-read |
| `JWT_METADATA_NAMESPACE` / `JWT_PAYLOAD_KEY` | `envoy.filters.http.jwt_authn` / `trial` | Must match the Envoy `jwt_authn` filter config |
| `*_AUTHZ_QUEUE_URL` (5 vars) | _(empty → idle consumer)_ | Leave blank to run without a given queue in local/partial setups |

---

## Security

Hard invariants — see [`ARCHITECTURE.md` §Threat model](ARCHITECTURE.md#threat-model) for the full STRIDE analysis:

1. **No JWT validation in this service.** Trust only claims Envoy's `jwt_authn` has already validated. No other claim or header is a valid identity/authz input.
2. **Client-supplied headers can never influence the six output headers.** They're built exclusively from server-side cached/fetched domain data.
3. **`mfa_freshness_seconds` is never cached** — a tenant tightening its MFA window takes effect immediately, not after up to 60s.
4. **Every Valkey key and outbound call is tenant-scoped by construction** — there's no separate access-control layer, since there's no database.
5. **Log redaction:** only `sub`/`iss` are ever logged, in structured JSON. `auth_time` and every other claim: never, by construction.

---

## CI

`.github/workflows/ci.yml`:

- **test** — unit (`-race`, coverage) + integration against real Valkey/LocalStack service containers, gated by `.github/scripts/coverage-gate.sh` (fails below 97%).
- **quality** — `fmt-check`, `vet`, `lint`, `arch-lint`, `mod-verify`, `vuln-check`.
- **build-image** — Hadolint + Docker build-to-cache (no local load), using the `GO_PRIVATE_TOKEN` secret for `platform-*` module resolution. `trivy` and `smoke` each restore their own copy from the GHA/registry cache rather than sharing a loaded image across jobs.
- **trivy** — CVE scan (fails on CRITICAL/HIGH/UNKNOWN), SARIF upload to the Security tab (best-effort — doesn't fail if GitHub Advanced Security isn't enabled), and a CycloneDX SBOM artifact.
- **smoke** — the liveness smoke test (`.github/scripts/smoke-tests.sh`) against the built image.
- **pr-summary** — posts/updates one status comment on pull requests once `test`/`quality`/`build-image`/`trivy`/`smoke` finish.
- **push** — on push to `main`/`master` only: builds (with SBOM + provenance attestations), pushes to `ghcr.io/bcbp-solutions-fzc-llc/iam-authz-enrichment`, and signs the image with Cosign (keyless, via Sigstore OIDC — no signing key to manage). Verify a published image with:
  ```sh
  cosign verify --certificate-identity-regexp "^https://github\.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/.github/workflows/.*@refs/heads/(main|master)$" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    ghcr.io/bcbp-solutions-fzc-llc/iam-authz-enrichment@<digest>
  ```

`.github/workflows/changelog-check.yml` separately fails a PR that touches `internal/` or `cmd/` without a `CHANGELOG.md` `[Unreleased]` entry.

There is no *tag-triggered* release workflow (versioned binaries, GitHub Releases, checksums) — pushes to `main` publish a `sha-<short-sha>`-tagged image, but nothing reacts to a `v*` tag yet. See [`CONTRIBUTING.md` § Deployment](CONTRIBUTING.md#deployment).

---

## Docker

```sh
make docker-up     # Valkey + LocalStack (SQS) only
make docker-down
```

The bundled `docker-compose.yml`'s `app` service builds this repo's own image — it requires `GO_PRIVATE_TOKEN` (a GitHub token with read access to `BCBP-SOLUTIONS-FZC-LLC` private repos) as a BuildKit secret:

```sh
docker build --secret id=go_private_token,env=GO_PRIVATE_TOKEN -t iam-authz-enrichment .
```

For local development, running `make docker-up` (Valkey + LocalStack only) and `make run` (the binary directly on the host) avoids needing that token at all — the Go module cache already has `platform-gincommon`/`platform-events` once fetched once with a valid token or SSH key.

---

## Out of scope

- Any durable schema, migration, or ORM — no Postgres, no database of any kind.
- JWT issuance, MFA enrollment, realm/tenant provisioning, the Keycloak Admin API.
- A policy-authoring UI — policies are Go code, compiled in, redeployed to change.
- Active session/token revocation (best-effort, owned elsewhere) — this service only bounds the *passive* cutoff via its own cache TTL.
- Rate limiting or quota enforcement — this service only injects `x-plan`/`x-feature-flags` for other components to act on.

---

## See also

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — layer model, request-flow/cache/event/failure-handling diagrams, key invariants, threat model.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — branch naming, PR checklist, commit style, how to extend each layer.
- [`docs/architecture/`](docs/architecture/) — standalone Mermaid diagram sources.
- `.go-arch-lint.yml` / `.golangci.yml` — the enforced dependency and lint rules.

## License / ownership

Private — BCBP Solutions FZC LLC. Internal platform service; not for external distribution.

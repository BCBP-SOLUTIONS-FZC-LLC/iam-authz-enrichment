# iam-authz-enrichment

Real-time authorization decisions for the platform: enriches every authenticated request with tenant, role, and permission context via a low-latency, cache-backed policy engine.

**Repository:** `github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment`
**Module:** Go 1.26.9+ · private module · stateless, 5–20 replicas, HPA on RPS · **no database**

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

There is no REST API. The only inbound interface is Envoy's `ext_authz` v3 gRPC contract, plus the standard `grpc.health.v1.Health` service (`Check`/`Watch`) for orchestrators that prefer a native gRPC health probe over the HTTP `/healthz` endpoint — both report the same signal (process startup, not dependency health; see § Local development's readiness note).

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
| `required_access_level` | Minimum tender-ACL grant level a tender-scoped action needs (`view`/`edit`/`approve`) — triggers the tender-ACL overlay if the tender is flagged restricted |

`tender_id` is **not** one of these — it's a per-resource ID, not static route metadata, so it can't be a `context_extensions` value the way the keys above can (Envoy has no mechanism to template a URL segment into a route's static `context_extensions` map per request). Instead it's parsed straight out of `CheckRequest.Attributes.Request.Http.Path` (`internal/adapter/inbound/grpc/requestfacts.go`'s `tenderIDFromPath`), matching the `/tenders/{id}` segment regardless of HTTP method — a route like `/api/v1/tenders/tender-1` or `/api/v1/tenders/tender-1/sections/3` yields `tender-1` whether the method is GET, POST, PATCH, or DELETE.

> **Route-design requirement.** Every tender-scoped route — `GET`, `POST`, `PUT`, `PATCH`, `DELETE` alike — **must** carry the tender ID as a `/tenders/{id}` URL path segment. `tenderIDFromPath` never reads a request body and never reads `context_extensions` for this value, so a route that only places the tender ID in a POST/PATCH/DELETE JSON body will silently skip the tender-ACL overlay for that route (`RequiresTenderACL()` sees an empty `TenderID` and returns `false`) instead of failing loudly — a restricted tender would not actually be protected on that route. This is the responsibility of whoever authors the Envoy/gateway route config for tender-scoped APIs, not something this service can detect or enforce on its own. See [`docs/lld/iam-lld-authz-enrichment.md`](docs/lld/iam-lld-authz-enrichment.md) §4.2 policy 8 and §16 AE-22 for the full rationale.

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
#
# Tender-scoped routes (GET/POST/PUT/PATCH/DELETE alike) MUST keep the tender
# ID as a /tenders/{id} URL path segment — never body-only — or the tender-ACL
# overlay silently doesn't apply to that route. See the Route-design
# requirement note above.
```

---

## Architecture

Clean Architecture — dependencies point inward; outer layers never import inner layers.

```
iam-authz-enrichment/
├── api/
│   ├── asyncapi.yaml                  # AsyncAPI 3.0 — 5 consumed channels, 15 event types, 0 published
│   └── embed.go                       # //go:embed asyncapi.yaml — served at GET /asyncapi · GET /asyncapi.yaml
├── cmd/server/                        # Composition root: config, logger, cache, org client, gRPC+HTTP servers, 5 SQS consumers
├── internal/
│   ├── domain/                        # Decision, DenyReason, MembershipContext, TenantContext, TenderACL, sentinel errors
│   │   └── policy/                    # Pure predicate functions — EvaluateBase, ViolatesReadOnly, MeetsDepartmentLevel (§3, no I/O)
│   ├── usecase/                       # Checker (§3.1 chain), Invalidator (§5), DecideDependencyOutcome (§7), RealmMap, RestrictedTenderSet
│   ├── adapter/
│   │   ├── inbound/
│   │   │   ├── grpc/                  # ext_authz v3 server — claims/request-facts decode, response encode
│   │   │   ├── http/                  # /healthz · /readyz · /asyncapi · /asyncapi.yaml — no business logic; /metrics has its own dedicated listener (see cmd/server)
│   │   │   └── consumer/              # 5 SQS consumers, one per §5 queue — LoadPlatform (SQS/SNS/outbox config), skipDuplicate/ackUnknown
│   │   └── outbound/
│   │       ├── valkey/                # Cache — ae:ctx · ae:tenant · ae:tender_acl · ae:neg · ae:processed
│   │       ├── orgmembership/         # HTTP client — I-8 memberships (Org & Membership), TAC-4/I-12 tender-acl (iam-tender-acl), I-14 mfa-freshness (Org & Membership)
│   │       ├── postgres/              # platform-pgcommon DSN/pool config, Zap logger adapter, OTel tracer — no live pool (HLD §5.4)
│   │       └── metrics/               # Prometheus authz_* series (§10)
│   └── config/                        # Load() — env vars only, no hot-reload (§11)
├── docs/
│   ├── lld/iam-lld-authz-enrichment.md  # Low-Level Design — precedence chain, cache-key table, §16 AE-# register
│   ├── architecture/                  # ARCHITECTURE.md's own supporting material — README.md + 7 Mermaid diagram sources
│   └── runbook.md                     # What to do when each Prometheus alert / CloudWatch DLQ alarm fires
├── deploy/
│   ├── helm/                          # Helm chart — no Ingress/HTTPRoute; Envoy reaches the grpc Service directly by cluster DNS
│   ├── iam/                           # Reference IAM policy + Terraform snippet (SQS consume-only — see deploy/iam/README.md)
│   └── monitoring/                    # Prometheus alerting rules + prometheus-adapter config for HPA decision-rate scaling,
│                                       # plus an illustrative DLQ CloudWatch-alarm Terraform snippet (see docs/runbook.md)
├── scripts/
│   ├── init-localstack.sh              # CI only (.github/workflows/validate-test.yml) — creates the 5 queues + their
│   │                                    # -dlq, maxReceiveCount=5 redrive policy, against a bare LocalStack service container
│   └── init-floci.sh                   # docker-compose/local dev only — identical 5 queues + DLQs, via floci (§ Local development)
└── test/
    ├── integration/                   # Real Valkey + real SQS — floci locally, LocalStack in CI (build tag `integration`)
    ├── e2e/                           # Real compiled binary over a real gRPC connection (build tag `e2e`) — see § Testing
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
| `adapter/inbound/*` | `usecase` + `domain` + `domain/policy`; the one exception is `http`, which additionally imports `api` directly (`asyncapi.go` reads the embedded `api/asyncapi.yaml` — a doc-serving leaf, not the orchestration layer) |
| `adapter/outbound/*` | `domain` + `domain/policy` only — **never** `usecase` |

### Storage and messaging

| Concern | Technology | Notes |
|---------|-----------|-------|
| **Cache** | Valkey (`go-redis/v9`) | The only persistent-ish state this service touches — no database, no ORM, no migrations |
| **Sibling services** | Org & Membership + iam-tender-acl (HTTP, mTLS) | Org & Membership: I-8 membership rebuild, I-14 MFA-freshness. iam-tender-acl: TAC-4 tender-ACL (formerly Org & Membership's I-12, repointed here ADR-0007 Wave 3 Phase 4). Both are the source of truth behind the cache |
| **Events (consumed)** | AWS SQS, 5 queues | `platform-events/v2` consumer; Glue-encoded envelopes decoded by the built-in `events.GlueDecodeCodec{}` (no separate decoder file, no Glue client needed); DLQ via SQS's own `maxReceiveCount=5` redrive policy — application code only logs the last delivery. Full contract: [`api/asyncapi.yaml`](api/asyncapi.yaml), also browsable live at `/asyncapi` (§ Common commands) |
| **Events (published)** | None | This service emits nothing to the bus |

### Shared library dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| `platform-gincommon` | v1.6.0 | zap logger, gRPC observability interceptors (panic-recovery/request-id/tracing/metrics/logging), Gin observability middlewares (`/healthz`/`/readyz`), health handler |
| `platform-events/v2` | v2.1.0 | SQS consumer loop (`LoadSQS` / `NewSQSConsumerWithClient` / `Envelope[T]` / `GlueDecodeCodec{}`), SNS/outbox config (`LoadSNS` / `LoadOutbox` / `RunnerConfigFromEnv`) matching iam-user-profile / iam-org-membership. **No publisher or runner**: this service consumes only (HLD §5.4); `cmd/server` skips `NewSNSPublisher` / `outbox.ApplySchema` / `NewRunner`. Dedup is `Envelope.ID` via `skipDuplicate` / `ackUnknown`; store is Valkey `SET NX` (no `processed_events` table). Import path: `github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2` |
| `platform-pgcommon/v2` | v2.0.1 | DSN/pool config (`ConfigFromEnv`), Zap logger adapter, OTel query tracer, `pgmetrics.InitWithIdentity` — same wiring as iam-user-profile / iam-org-membership. **No live pool**: this service has no schema (HLD §5.4); `cmd/server` loads `PoolConfig` then skips `NewPool` / migrate / outbox. Import path: `github.com/BCBP-SOLUTIONS-FZC-LLC/platform-pgcommon/v2` |
| `go-redis/v9` | v9.23.0 | Valkey/Redis client — the only non-platform library with a significant version; import path `github.com/redis/go-redis/v9` |

---

## Event architecture

This service is a **pure event consumer** — it subscribes to five SQS queues and publishes **zero** events. `cmd/server` still loads platform-events SNS and outbox config (`LoadSNS` / `LoadOutbox` / `RunnerConfigFromEnv`) so operators see the same `SNS_*` / `OUTBOX_*` warnings as iam-user-profile / iam-org-membership, then skips `NewSNSPublisher`, `outbox.ApplySchema`, and `NewRunner` (HLD §5.4 / EVT-2). Every event received is a cache-invalidation trigger against this service's own Valkey cache, never a domain state mutation of its own.

The full machine-readable contract is [`api/asyncapi.yaml`](api/asyncapi.yaml) — 15 event types across 5 channels, `receive`-only operations, per-event consumer behavior (`x-consumer-behavior`) and payload schemas, verified field-for-field against the producing services' own asyncapi.yaml where one was available (Org & Membership, User Profile, Realm Provisioner) and explicitly flagged `producer-lifecycle-status: unknown` where it wasn't (Billing Service, Tender Service). Browse it live at `GET /asyncapi` (HTML catalog) or `GET /asyncapi.yaml` (raw spec) — see [§ Environment variables](#environment-variables) for the `DOCS_ENABLED`/`DOCS_AUTH_TOKEN` gate. See [`docs/lld/iam-lld-authz-enrichment.md` §7](docs/lld/iam-lld-authz-enrichment.md) for the full narrative per-event rationale this table summarizes, and [`ARCHITECTURE.md` § Event flow](ARCHITECTURE.md#event-flow) for the dedup/DLQ sequence diagram.

**Envelope shape:** `{id, type, tenant_id, time, data}` — `tenant_id` is a top-level envelope field, never duplicated inside `data`; the `billing-authz-q` events below read only that field, no `data` decode at all.

**Idempotency:** platform-events has no processed-events API — the library contract is `Envelope.ID` as the idempotency key, the same `skipDuplicate` / `ackUnknown` helpers iam-org-membership / iam-user-profile use. Those siblings persist that to a Postgres `processed_events` table (`INSERT … ON CONFLICT DO NOTHING`). This service has no database, so the store is a Valkey `SET NX` on `ae:processed:{event_id}` (7-day TTL). **DLQ:** all five queues use the identical SQS-native `maxReceiveCount=5` redrive (`scripts/init-localstack.sh` in CI, `scripts/init-floci.sh` for local dev), never application code — a DLQ'd message degrades to "this cache entry may be stale until its TTL naturally expires" (5–60s), not a correctness failure requiring replay.

**`membership-authz-q`** (Org & Membership, 6 event types) — all evict the per-user `ae:ctx`/`ae:neg` slice:

| Event type | Consumed field(s) | Effect |
|---|---|---|
| `DepartmentMembershipGranted` | `user_id` | Evict `ae:ctx:{tenant}:{user}` + `ae:neg:{tenant}:{user}` |
| `DepartmentMembershipRevoked` | `user_id` | Same as above |
| `DepartmentMembershipLevelChanged` | `user_id` | Same as above |
| `TenantRoleGranted` | `user_id` | Same as above |
| `TenantRoleRevoked` | `user_id` | Same as above |
| `MembershipRevoked` | `tenant_id`, `user_id` | Same as above, **plus** best-effort evict every `ae:tender_acl:{tenant}:*:{user}` entry — the whole-membership-removal cascade signal (LLD §16 AE-20); the only event here with a wider eviction, since a full removal leaves per-grant rows inert instead of firing the five events above individually |

**`user-authz-q`** (User Profile, 3 event types):

| Event type | Consumed field(s) | Effect |
|---|---|---|
| `UserUpdated` | `user_id`, `changed_fields` | Evict `ae:ctx`/`ae:neg` **only if** `"email"` is in `changed_fields` — the one event in this document with a payload-content filter; every other value is a no-op |
| `UserAvailabilityChanged` | `user_id` | Evict `ae:ctx:{tenant}:{user}` + `ae:neg:{tenant}:{user}` unconditionally — historically load-bearing for `active_delegations[]`, now a harmless no-op-equivalent eviction since delegation state was extracted (LLD §16 AE-18) |
| `UserDeleted` | `user_id` | Evict `ae:ctx`/`ae:neg`, plus best-effort evict every `ae:tender_acl:{tenant}:*:{user}` entry |

**`billing-authz-q`** (Billing Service, 3 event types) — all evict the same single tenant-scoped key regardless of which fired, no payload decode beyond the envelope's own `tenant_id`:

| Event type | Consumed field(s) | Effect |
|---|---|---|
| `TenantPlanChanged` | _(envelope `tenant_id` only)_ | Evict `ae:tenant:{tenant}` |
| `TenantSubscriptionCancelled` | _(envelope `tenant_id` only)_ | Evict `ae:tenant:{tenant}` |
| `TenantReactivated` | _(envelope `tenant_id` only)_ | Evict `ae:tenant:{tenant}` |

**`tenant-authz-q`** (Realm Provisioner, 2 event types) — keep the in-process realm→tenant map fresh for JWT-issuer-based tenant resolution (LLD §8.3); both must be wired. The Realm Provisioner always co-emits both events (RP-2 direct-paid signup and RP-3 trial→dedicated conversion each emit `TenantRealmReady` followed by `TenantConverted` in the same outbox transaction). The SNS subscription filter for this queue **must include both** `EventType` values — omitting `TenantRealmReady` leaves `HandleTenantRealmReady` as dead code and breaks any future provisioning path that may emit it without a co-emitted `TenantConverted`:

| Event type | Consumed field(s) | Effect |
|---|---|---|
| `TenantConverted` | `realm` | Update the realm→tenant map, **plus** evict `ae:tenant:{tenant}` (the realm strategy changed) |
| `TenantRealmReady` | `realm` | Update the realm→tenant map only — **no** cache eviction |

**`tender-authz-q`** (Tender Service, 1 event type) — flips an in-process fact, not a Valkey write:

| Event type | Consumed field(s) | Effect |
|---|---|---|
| `TenderRestricted` | `tender_id` | Mark `(tenant, tender_id)` restricted in the in-process `RestrictedTenderSet` — the §3.1 step-4 tender-ACL overlay only calls out to TAC-4 for a tender this set marks restricted |

---

## Cross-service dependencies

### 1. Synchronous outbound calls (this service → other services)

Every `Authorization.Check` traverses the §3.1 precedence chain. Not every call reaches every dependency — the table below shows when each is hit:

| Dependency | When called | Adapter package | Posture | On failure |
|---|---|---|---|---|
| **Valkey** | Every `Check()` — cache read (`ae:ctx`, `ae:tenant`) | `outbound/valkey/` | soft — bypass | Call Org & Membership directly for this request; a Valkey miss is not an error |
| **Org & Membership** (`ORG_MEMBERSHIP_BASE_URL`) | Cache miss or Valkey unavailable — I-8 membership rebuild | `outbound/orgmembership/` | stale-if-error, capped 5 min | Stale `ae:ctx`/`ae:tenant` entry present → serve it (§7 row 2). No stale entry → `DENY_SERVICE_UNAVAILABLE` (§7 row 3) |
| **Org & Membership** (`ORG_MEMBERSHIP_BASE_URL`) | Approver-gated requests only — I-14 MFA-freshness | `outbound/orgmembership/` | fail-closed | `DENY_MFA_STALE` — **never cached**; a sibling outage on this check is treated as "can't confirm freshness", not "service unavailable" |
| **iam-tender-acl** (`TENDER_ACL_BASE_URL`) | Restricted tender-scoped requests only — TAC-4 tender-ACL | `outbound/orgmembership/` | fail-closed, overlay only | `DENY_TENDER_ACL_INSUFFICIENT` — never escalates to `DENY_SERVICE_UNAVAILABLE`; does not affect non-tender aspects of the same request |

The common path at 95%+ cache-hit rate hits **Valkey only** — no synchronous sibling call at all.

`mfa_freshness_seconds` is a **hard security invariant**: it is never written into `ae:ctx` or any other Valkey key. A code path that folds it into a cached envelope is a security regression, not a performance optimization — there is a dedicated regression test for this.

### 2. Inbound callers (other services → this service)

| Caller | Interface | Purpose |
|---|---|---|
| **Envoy** | gRPC `envoy.service.auth.v3.Authorization/Check` | The sole inbound interface — called on every authenticated request the gateway proxies. Envoy's `jwt_authn` validates the JWT first; this service reads only the already-validated metadata (`MetadataContext`), never raw headers |

No other service calls this service directly. There is no REST or HTTP business API.

### 3. Async event dependencies

**Events this service consumes** (cache-invalidation only — no domain state of its own is mutated, nothing is published):

| Queue | Producer | Event types | Action |
|---|---|---|---|
| `membership-authz-q` | Org & Membership | `DepartmentMembershipGranted`, `DepartmentMembershipRevoked`, `DepartmentMembershipLevelChanged`, `TenantRoleGranted`, `TenantRoleRevoked`, `MembershipRevoked` | Evict `ae:ctx`/`ae:neg` for the user; `MembershipRevoked` additionally performs a best-effort eviction of all `ae:tender_acl:{tenant}:*:{user}` entries — the whole-membership-removal cascade signal (LLD §16 AE-20) |
| `user-authz-q` | User Profile (`iam-user-profile`) | `UserUpdated`, `UserAvailabilityChanged`, `UserDeleted` | Evict `ae:ctx`/`ae:neg`; `UserUpdated` only evicts if `"email"` appears in `changed_fields`; `UserDeleted` also evicts all `ae:tender_acl` entries for the user |
| `billing-authz-q` | Billing Service | `TenantPlanChanged`, `TenantSubscriptionCancelled`, `TenantReactivated` | Evict `ae:tenant:{tenant}` — no payload decode beyond the envelope's `tenant_id` |
| `tenant-authz-q` | Realm Provisioner | `TenantConverted`, `TenantRealmReady` | Update in-process realm→tenant map; `TenantConverted` also evicts `ae:tenant:{tenant}` (realm strategy changed) |
| `tender-authz-q` | Tender Service | `TenderRestricted` | Mark `(tenant, tender_id)` restricted in in-process `RestrictedTenderSet` — gates whether TAC-4 is called on subsequent tender-scoped `Check()` calls |

**Events this service produces:** **None.** This service is a pure consumer. `NewSNSPublisher` / `outbox.ApplySchema` / `NewRunner` are never called (HLD §5.4 / EVT-2). The full machine-readable consumer contract is [`api/asyncapi.yaml`](api/asyncapi.yaml), also browsable live at `GET /asyncapi`.

### 4. Infrastructure dependencies

| System | Role |
|---|---|
| **Valkey** (Redis-compatible) | The only persistent-ish state this service touches — `ae:ctx`, `ae:tenant`, `ae:tender_acl`, `ae:neg`, `ae:processed` cache keys; no database, no ORM, no migrations |
| **AWS SQS** (5 queues + 5 DLQs) | `membership-authz-q`, `user-authz-q`, `billing-authz-q`, `tenant-authz-q`, `tender-authz-q`; DLQ via SQS-native `maxReceiveCount=5` redrive — no application-layer DLQ code; a DLQ'd message degrades to a stale cache entry until its TTL expires, not a correctness failure |
| **Envoy** (inbound only) | The API gateway / service mesh proxy — the sole caller of `Authorization.Check`. `jwt_authn` validates JWTs upstream; this service reads only Envoy-injected `MetadataContext`, never raw headers |

---

## Local development

### Prerequisites

- Go 1.26.9+
- Docker (for `make docker-up` — Valkey + floci SQS, plus floci-ui, a web console for floci)
- SSH key or `GO_PRIVATE_TOKEN` registered for `github.com/BCBP-SOLUTIONS-FZC-LLC` (for `platform-gincommon`/`platform-events`/`platform-pgcommon`)

### Setup

```sh
make setup       # copy .env-example to .env
make docker-up   # start Valkey + floci (SQS) + floci-ui — scripts/init-floci.sh creates the 5 queues + DLQs
make run         # go run ./cmd/server
```

`/healthz`, `/readyz` are served on `APP_PORT` (default `8080`); `/metrics` is served separately on `METRICS_PORT` (default `9090`); the `ext_authz` gRPC service listens on `GRPC_PORT` (default `9091`). `/asyncapi` (HTML event-contract viewer) and `/asyncapi.yaml` (raw spec) are also on `APP_PORT` — always on outside `APP_ENV=production`, opt-in in production via `DOCS_ENABLED` — try `http://localhost:8080/asyncapi` after `make run`.

### Common commands

Run `make help` for the full list.

```sh
make build            # compile bin/iam-authz-enrichment
make test             # unit tests — fakes only, no Docker required
make test-integration # real Valkey + floci SQS (requires make docker-up first)
make test-e2e         # real binary over a real gRPC connection (requires make build + make docker-up first)
make lint              # golangci-lint
make arch-lint          # enforce .go-arch-lint.yml component boundaries
make cover              # coverage profile + open HTML report
make ci                 # the full local gate: tidy + fmt-check + vet + lint + arch-lint + observability-lint + database-lint + test-ci + build
make observability-lint # enforce all logs/metrics/traces pass through platform-gincommon only
make database-lint      # enforce all DB connections/config/ops pass through platform-pgcommon only
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
  "departments": [{"department_id": "fd72f513-45f0-46ca-a1ed-9183be72484c", "role_level": "reviewer"}],
  "plan": "pro",
  "feature_flags": ["flag-a"],
  "subscription_status": "active",
  "read_only": false,
  "mfa_freshness_seconds": 300
}
EOF
(cd mockorg && python3 -m http.server 8081) &

# restart the service pointed at the mock (default 10ms ORG_MEMBERSHIP_TIMEOUT
# is too tight for Python's dev server — give it real headroom). Also point
# TENDER_ACL_BASE_URL at the same mock server up front — the tender-ACL
# overlay walkthrough below (TAC-4, formerly I-12) reuses this one server
# for both, since its paths (/api/v1/internal/users/... vs.
# /internal/tenants/...) don't collide.
ORG_MEMBERSHIP_BASE_URL=http://localhost:8081 ORG_MEMBERSHIP_TIMEOUT=2s \
TENDER_ACL_BASE_URL=http://localhost:8081 TENDER_ACL_TIMEOUT=2s make run
```

Re-running the same `grpcurl`/`grpcui` `Check` call from above (`sub: "alice"`, `tenant_id: "tenant-acme"`) now returns `okResponse` with all six headers (`x-tenant-id: tenant-acme`, `x-user-id: alice`, `x-departments: fd72f513-45f0-46ca-a1ed-9183be72484c:reviewer`, `x-tenant-roles: tenant_admin`, `x-plan: pro`, `x-feature-flags: flag-a`) instead of a denial. `department_id` is a UUID here to match the real Org & Membership schema (`departments.id`) — this service passes whatever string the sibling sends straight through as `<department_id>:<level>` (`internal/usecase/check.go`'s `buildHeaders`) without interpreting its format, so the mock could use any string, but a UUID is what production actually looks like.

From there, edit the JSON file (or the request) to exercise other branches of §3.1 without touching any code:
- A `sub` with no matching file → 404 → `DENY_UNRESOLVABLE_SUBJECT`.
- `"read_only": true` in the mock file + `"method": "POST"` in the request → `DENY_TENANT_READ_ONLY`.
- Add `"context_extensions": {"policy_action": "manage_department_memberships"}` under `attributes` with a mock user that has no `tenant_admin`/`tenant_owner` role → `DENY_ROLE_INSUFFICIENT`.

`mockorg/` is a throwaway local directory — already covered by `.gitignore` (`mockorg*`), never commit it.

#### Testing the tender-ACL overlay (§3.1 step 4)

This overlay only runs when a request is tender-scoped *and* the tender has been flagged restricted via a real `TenderRestricted` event (§5) — there's no direct way to flip it, by design (§2: this service never invents policy state, it only reacts to events). Add the TAC-4 mock (formerly I-12 — note the path has **no** `/api/v1` prefix, unlike every Org & Membership mock above: iam-tender-acl registers this route directly under `/internal`, see its LLD §8.3), then walk through all three states.

```sh
mkdir -p mockorg/internal/tenants/tenant-acme/tenders/tender-1/acl
cat > mockorg/internal/tenants/tenant-acme/tenders/tender-1/acl/alice <<'EOF'
{"has_access": true, "access_level": "approve", "expires_at": "2026-08-12T00:00:00Z"}
EOF
```

**1. Not flagged restricted yet** — the overlay is skipped entirely (default department membership is enough), even with a `/tenders/{id}` path and `required_access_level` set on the request:

```sh
grpcurl -plaintext -d '{
  "attributes": {
    "metadata_context": { "filter_metadata": { "envoy.filters.http.jwt_authn": { "trial": {
      "sub": "alice", "iss": "https://kc.example.com/realms/shared-trial", "tenant_id": "tenant-acme"
    }}}},
    "request": { "http": { "method": "GET", "path": "/api/v1/tenders/tender-1" } },
    "context_extensions": { "required_access_level": "view" }
  }
}' localhost:9091 envoy.service.auth.v3.Authorization/Check
```
→ `okResponse` (Allow).

**2. Flag it restricted**, then re-run the exact same `Check` call — now it actually calls TAC-4 (iam-tender-acl), gets `access_level: "approve"` (satisfies the required `"view"`), and still allows:

```sh
EVENT_ID=$(uuidgen 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())')
docker compose exec floci aws sqs send-message \
  --queue-url http://floci:4566/000000000000/tender-authz-q \
  --region ap-south-1 \
  --message-body "{
    \"id\": \"$EVENT_ID\", \"type\": \"TenderRestricted\", \"tenant_id\": \"tenant-acme\",
    \"time\": \"2026-08-12T00:00:00Z\", \"data\": {\"tender_id\": \"tender-1\"}
  }"
sleep 2   # let the consumer pick it up before re-running Check
```

**3. Flip the mock to an insufficient grant** and re-run `Check` a third time — now `DENY_TENDER_ACL_INSUFFICIENT`:

```sh
cat > mockorg/internal/tenants/tenant-acme/tenders/tender-1/acl/alice <<'EOF'
{"has_access": false, "access_level": "", "expires_at": "2026-08-12T00:00:00Z"}
EOF
```

Note `ae:tender_acl:*` caches for 15s (§4.1) — if you flip the mock and re-run within that window against an *already-cached* grant, you'll still see the old cached result. Wait a beat, or just don't worry about it: real TAC-4 answers never 404 or flap this fast in production.

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

The five SQS queues are created automatically by `docker compose up` (via `scripts/init-floci.sh`, mounted as a [floci](https://github.com/floci-io/floci) ready-hook — an open-source, always-free LocalStack-compatible AWS emulator, the same image `iam-org-membership`/`iam-delegation` use for their own local dev). To drive one manually you need an AWS CLI — either your own, or the one already baked into the floci container (no local install required):

```sh
# Option A: your own AWS CLI (brew install awscli), pointed at floci
aws --endpoint-url=http://localhost:4571 sqs list-queues --region ap-south-1

# Option B: no install — run it through the container instead
docker compose exec floci aws --region ap-south-1 sqs list-queues
```

Every command below works with either CLI — swap `aws --endpoint-url=http://localhost:4571` for `docker compose exec floci aws --region ap-south-1` if you're using Option B:

```sh
# 1. Start infrastructure
make docker-up

# 2. Verify the queues exist
docker compose exec floci aws --region ap-south-1 sqs list-queues

# 3. Start the service (separate terminal)
make run

# 4. Send an event — e.g. a DepartmentMembershipGranted. Use a FRESH "id"
#    every time you run this: MarkProcessed (§5's idempotency guard) marks
#    each event ID processed for 7 days, so resending the same literal "id"
#    is correctly treated as a duplicate — the handler is skipped and
#    nothing gets evicted. That's the dedup contract working, not a bug.
EVENT_ID=$(uuidgen 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())')
docker compose exec floci aws sqs send-message \
  --queue-url http://floci:4566/000000000000/membership-authz-q \
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

#### Verify queue state in the browser (floci-ui)

`make docker-up` also starts **floci-ui**, a web console for floci, at **http://localhost:4502**. It's a faster way to confirm an event landed on the right queue — and that its DLQ redrive is behaving — than shelling into the CLI each time:

1. Open **http://localhost:4502** → sidebar → **Integration → SQS**. You'll see all ten queues `init-floci.sh` provisioned (`membership-authz-q`/`membership-authz-q-dlq`, `user-authz-q`/`-dlq`, `billing-authz-q`/`-dlq`, `tenant-authz-q`/`-dlq`, `tender-authz-q`/`-dlq`), each with a **Messages** column.
2. Run step 4 above (or the tender-ACL overlay's `TenderRestricted` send-message, above) and watch the target queue's **Messages** count — it should go to `1` immediately, then back to `0` once the running service's consumer picks it up (§5's idempotent `MarkProcessed`/`EvictProcessed` handler).
3. **Not (yet) shown by floci-ui**: message bodies — it reports queue metadata (message counts, ARN, retention) only, no message browser. Use `docker compose exec floci aws --region ap-south-1 sqs receive-message --queue-url http://floci:4566/000000000000/<queue> --wait-time-seconds 1` for that (be aware this competes with the running service's own long-poll consumer for the same message — stop `make run` first if you want a guaranteed read).

This service publishes nothing (§1: five inbound queues, zero outbound), so unlike `iam-org-membership`'s/`iam-delegation`'s own floci-ui walkthroughs there's no SNS topic/subscription view to check here — the SQS tab above is the whole picture.

See [§ Event architecture](#event-architecture) for the full per-queue event-type table, and [`ARCHITECTURE.md` § Event flow](ARCHITECTURE.md#event-flow) for the dedup/DLQ sequence diagram.

---

## Testing

- **Unit** (`internal/.../*_test.go`) — hand-written fakes (`test/fixtures`), no gomock/mockery, no Docker. Includes the §12 acceptance checklist: contract tests, one eviction test per event type, tenant-resolution edge cases, one test per §7 failure-matrix row, the `mfa_freshness_seconds`-never-cached regression, the header-spoofing regression, precedence-order tests, and the convergence-without-events vs. stale-if-error distinction test.
- **Integration** (`test/integration`, build tag `integration`) — real Valkey (via `miniredis` is unit-only; this tier uses the actual `docker-compose` Valkey) + real SQS via floci (§ Testing events locally, above), including an end-to-end DLQ test that waits for 5 real redeliveries.
- **E2E** (`test/e2e`, build tag `e2e`) — the one tier that starts the actual compiled binary and drives it over a real gRPC connection, rather than exercising one adapter directly against a fake. Catches what the two tiers above structurally can't: a wiring/config regression that only shows up when every real dependency is reachable at once (an env var renamed but not propagated to the Helm chart, a `context_extensions` key that stops round-tripping through the real wire format). Covers the full §3.1 precedence chain end to end, including a real `DepartmentMembershipGranted` event proving cache eviction actually happens over the wire and a real `TenderRestricted` event driving the tender-ACL overlay through all three states. Requires the binary built first (`make build`) and real Valkey/SQS up (`make docker-up`).
- **Load** (`test/load`) — manual 500 RPS harness against a running instance, both `-mode=hit` (95%+ cache-hit target) and `-mode=miss` (100% cache-miss latency floor). Not run in CI. Run once locally (Valkey + floci up, a generic mock Org & Membership responder on `:8081`, `make run`) at 500 RPS/30s each: **hit** p50=0.82ms p95=1.29ms p99=1.68ms; **miss** p50=0.83ms p95=1.65ms p99=3.18ms — comfortably inside the documented 15ms/50ms budgets. **Caveat that matters**: this was a single-machine loopback-network test against a trivial Python mock, not a real network hop to a real Org & Membership instance on real cluster hardware — treat these as a sanity check that the harness and the code path work, not as validated production SLO evidence. Re-run against a real staging deployment before trusting the `AuthzEnrichmentDecisionLatencySLOBreach` alert's 50ms threshold on a new cluster.

```sh
make test              # unit
make docker-up && make test-integration
make build && make test-e2e
make load-test         # manual — see test/load
```

Coverage target: 100% statements on `internal/...`, enforced via `make test-ci` (`-race`, `-coverpkg` spanning every adapter/usecase/domain package). `NoopRecorder`'s empty-bodied methods (`internal/usecase/ports.go`) always show 0.0% individually — Go's coverage tool can't instrument a function with zero statements — but they contribute 0/0 and don't affect the total.

---

## Environment variables

See [`.env-example`](.env-example) for the full annotated list. Key ones:

| Variable | Default | Notes |
|----------|---------|-------|
| `APP_PORT` / `METRICS_PORT` / `GRPC_PORT` | `8080` / `9090` / `9091` | HTTP (health only), metrics (`/metrics`, separate listener), and gRPC (`ext_authz`) listen ports |
| `VALKEY_URL` | `localhost:6379` | `.env-example` recommends `localhost:6384` for local dev; **must use `rediss://` scheme (TLS) outside `APP_ENV=dev`** — startup fails fast on a plaintext URL in non-dev, since the cache holds authorization context |
| `DOCS_ENABLED` / `DOCS_AUTH_TOKEN` | `false` / _(empty)_ | Opt-in switch for `/asyncapi`/`/asyncapi.yaml` in production (always on outside `APP_ENV=production`); `DOCS_AUTH_TOKEN` optionally bearer-token-gates them once enabled; startup warns when `DOCS_ENABLED=true` in production without `DOCS_AUTH_TOKEN` |
| `AE_CTX_TTL` / `AE_CTX_JITTER` | `60s` / `6s` | §4.1 — desyncs expiry across replicas |
| `AE_TENDER_ACL_TTL` / `AE_NEG_TTL` | `15s` / `5s` | Half the sibling's own TTL / negative-cache storm collapse |
| `AE_RESTRICTED_NEG_TTL` / `AE_REALM_NEG_TTL` | `5s` each | L1 negative-cache TTLs for `RestrictedTenderSet`/`RealmMap` — separate from `AE_NEG_TTL` since each bounds a distinct security-propagation delay (how fast a replica notices another replica's write), not a shared performance knob |
| `AE_PROCESSED_EVENT_TTL` | `192h` (8 days) | PE-1: must be strictly > 7-day SQS message lifetime to guarantee redelivered messages are still recognized as processed |
| `AE_STALE_IF_ERROR_MAX_AGE` | `5m` | Hard-capped at 5m regardless of configured value (§7) |
| `ORG_MEMBERSHIP_BASE_URL` / `_TIMEOUT` | `http://localhost:8081` / `10ms` | I-8/I-14. Aggressive timeout — headroom inside the 15ms p99 budget |
| `TENDER_ACL_BASE_URL` / `TENDER_ACL_TIMEOUT` | `http://localhost:8086` / `20ms` | TAC-4 (formerly I-12) against iam-tender-acl, ADR-0007 Wave 3 Phase 4 — sized against that service's own 5ms-hit/20ms-miss SLO, not reused from `ORG_MEMBERSHIP_TIMEOUT` |
| `SHARED_REALM_ISSUER` | _(empty)_ | Keycloak issuer for the shared trial realm. **At least one of `SHARED_REALM_ISSUER` or `REALM_TENANT_MAP_SEED` must be set outside `APP_ENV=dev`** — both empty causes a startup failure (every request would silently return `DENY_MALFORMED_IDENTITY`) |
| `REALM_TENANT_MAP_SEED` | `{}` | Startup-only JSON `{"realm": "tenant_id"}` seed for dedicated realms; kept fresh at runtime by `tenant-authz-q` events, never re-read after startup |
| `JWT_METADATA_NAMESPACE` / `JWT_PAYLOAD_KEY` | `envoy.filters.http.jwt_authn` / `trial` | Must match the Envoy `jwt_authn` filter config |
| `*_AUTHZ_QUEUE_URL` (5 vars) | _(empty → idle consumer)_ | Leave blank to run without a given queue in local/partial setups (`APP_ENV=dev` only — required, and must be pairwise distinct, outside dev; `config.Load()` fails fast otherwise) |
| `*_AUTHZ_QUEUE_CONCURRENCY` (5 vars) | `4` each | `events.WithConcurrency` per queue — messages handed to handler goroutines at once, instead of `platform-events`' library default of `1` (fully serial per queue) |
| `DATABASE_URL` / `PG_*` / `PG_STATEMENT_TIMEOUT` | _(empty)_ | Loaded via `platform-pgcommon` `ConfigFromEnv` / `DSNFromEnv` / `PoolConfig` — same path as iam-user-profile / iam-org-membership. **Leave unset**: this service has no schema; `cmd/server` never calls `NewPool` / migrate |
| `SNS_TOPIC_ARN` / `OUTBOX_*` | _(empty)_ | Loaded via `platform-events` `LoadSNS` / `LoadOutbox` / `RunnerConfigFromEnv` — same path as siblings. **Leave unset**: this service publishes nothing; `cmd/server` never calls `NewSNSPublisher` / `outbox.ApplySchema` / `NewRunner` |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | `test` | Dummy floci credentials (use IRSA in production — reference IAM policy + Terraform snippet under [`deploy/iam/`](deploy/iam/)) |
| `GRPC_MAX_RECV_MSG_SIZE_BYTES` / `_SEND_` | `262144` (256KiB) | Defense-in-depth, not a real operating limit — `CheckRequest`/`CheckResponse` are small |
| `GRPC_TLS_CERT_FILE` / `_KEY_FILE` / `_CLIENT_CA_FILE` | _(empty → plaintext)_ | App-level TLS/mTLS for deployments with no service-mesh sidecar or CNI-level encryption — see § Security |

Startup fails fast (not silently) on all of the following outside `APP_ENV=dev`:
- `ORG_MEMBERSHIP_BASE_URL` or `TENDER_ACL_BASE_URL` left at its local-dev default
- `VALKEY_URL` without `rediss://` scheme (authorization context must be encrypted in transit)
- Both `SHARED_REALM_ISSUER` and `REALM_TENANT_MAP_SEED` empty (no tenant-resolution path)
- Any of the five `*_AUTHZ_QUEUE_URL` vars blank
- Any two queue URLs set to the same value

See `docs/runbook.md` for startup-failure troubleshooting.

---

## Security

Hard invariants — see [`ARCHITECTURE.md` §Threat model](ARCHITECTURE.md#threat-model) for the full STRIDE analysis:

1. **No JWT validation in this service.** Trust only claims Envoy's `jwt_authn` has already validated. No other claim or header is a valid identity/authz input.
2. **Client-supplied headers can never influence the six output headers.** They're built exclusively from server-side cached/fetched domain data.
3. **`mfa_freshness_seconds` is never cached** — a tenant tightening its MFA window takes effect immediately, not after up to 60s.
4. **Every Valkey key and outbound call is tenant-scoped by construction** — there's no separate access-control layer, since there's no database.
5. **Log redaction:** only `sub`/`iss` are ever logged, in structured JSON. `auth_time` and every other claim: never, by construction.
6. **Transport encryption is assumed, not enforced, by default.** The gRPC server listens in plaintext unless `GRPC_TLS_CERT_FILE`/`GRPC_TLS_KEY_FILE` are set — "Envoy calls this service over mTLS" describes the *intended* deployment (a service mesh sidecar or the CNI layer terminating mTLS transparently), which this repo cannot verify from here. **Confirm the target cluster actually has one of those before shipping real traffic**, or set the `GRPC_TLS_*` env vars (`deploy/helm/values.yaml`'s `grpcTLS.enabled`) to terminate TLS/mTLS in the app itself. `NetworkPolicy` alone is L3/L4 segmentation — it does not encrypt anything.

---

## CI

`.github/workflows/ci.yml`:

- **validate-test** — two parallel jobs, each with its own real Valkey/LocalStack service containers: `test` (unit `-race`+coverage, gated by `.github/scripts/coverage-gate.sh` at 100%, plus integration) and `e2e` (builds the binary, then runs it over a real gRPC connection). `ci.yml`'s downstream jobs (`smoke`/`trivy`) gate on the whole `validate-test` workflow, so both must pass.
- **validate-quality** — `fmt-check`, `vet`, `lint`, `arch-lint`, `mod-verify`, `vuln-check`.
- **build-image** — Hadolint + Docker build-to-cache (no local load), using the `GO_PRIVATE_TOKEN` secret for `platform-*` module resolution. `trivy` and `smoke` each restore their own copy from the GHA/registry cache rather than sharing a loaded image across jobs.
- **trivy** — CVE scan (fails on CRITICAL/HIGH/UNKNOWN), SARIF upload to the Security tab (best-effort — doesn't fail if GitHub Advanced Security isn't enabled), and a CycloneDX SBOM artifact.
- **smoke** — the liveness smoke test (`.github/scripts/smoke-tests.sh`) against the built image.
- **pr-summary** — posts/updates one status comment on pull requests once `validate-test`/`validate-quality`/`build-image`/`trivy`/`smoke` finish.
- **push** — on push to `main`/`master` only: builds (with SBOM + provenance attestations), pushes to `ghcr.io/bcbp-solutions-fzc-llc/iam-authz-enrichment`, and signs the image with Cosign (keyless, via Sigstore OIDC — no signing key to manage). Verify a published image with:
  ```sh
  cosign verify --certificate-identity-regexp "^https://github\.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/.github/workflows/.*@refs/heads/(main|master)$" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    ghcr.io/bcbp-solutions-fzc-llc/iam-authz-enrichment@<digest>
  ```

`.github/workflows/changelog-check.yml` separately fails a PR that touches `internal/` or `cmd/` without a `CHANGELOG.md` `[Unreleased]` entry.

Pushing a `v*` tag triggers `.github/workflows/release.yml` — validate → build (CHANGELOG gate + 5-platform binaries) → docker (semver-tagged image, CVE scan, SBOM, SLSA provenance, Cosign sign) → deploy-gate (live Helm deploy + health check, auto-rollback) → publish (GitHub Release with everything attached). See [`CONTRIBUTING.md` § Deployment](CONTRIBUTING.md#deployment) for the full pipeline, required secrets, and the gRPC-specific health query.

`validate-test`/`validate-quality` live in `.github/workflows/validate-test.yml`/`validate-quality.yml` (reusable workflows) so `ci.yml` and `release.yml` share exactly one definition of each gate.

---

## Versioning and releases

| Version bump | When |
|---|---|
| **MAJOR** | Breaking change to the runtime contract — `DenyReason` values, the six injected headers, `CheckRequest` field usage, required env vars, `values.yaml` shape |
| **MINOR** | New backward-compatible capability |
| **PATCH** | Bug fix, performance improvement, documentation correction |

```bash
# Tag and push triggers the release workflow automatically.
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

See [VERSIONING.md](VERSIONING.md) for the full SemVer rules, what counts as the runtime contract, supported releases, image-tag/pin scheme, and the complete maintainer release checklist.

---

## Docker

```sh
make docker-up     # Valkey + floci (SQS) + floci-ui only
make docker-down
```

The bundled `docker-compose.yml`'s `app` service builds this repo's own image — it requires `GO_PRIVATE_TOKEN` (a GitHub token with read access to `BCBP-SOLUTIONS-FZC-LLC` private repos) as a BuildKit secret:

```sh
docker build --secret id=go_private_token,env=GO_PRIVATE_TOKEN -t iam-authz-enrichment .
```

For local development, running `make docker-up` (Valkey + floci only) and `make run` (the binary directly on the host) avoids needing that token at all — the Go module cache already has `platform-gincommon`/`platform-events`/`platform-pgcommon` once fetched once with a valid token or SSH key.

---

## Dependency posture

Every `Check()` touches at most two synchronous dependencies (Valkey, Org & Membership) plus, on tender-scoped/approver-gated routes, up to two more (iam-tender-acl, Org & Membership's MFA-freshness endpoint). §7's failure matrix (`internal/usecase/failure.go`'s `DecideDependencyOutcome`) governs the first two; the tender-ACL and MFA-freshness calls each have their own independent, narrower fail-closed rule.

| Dependency call | Posture | On failure |
|---|---|---|
| Valkey (`ae:ctx`/`ae:tenant` read) | soft — bypass | Org & Membership still reachable → call it directly for this request, skipping the cache (§7 row 1). Correctness is preserved since the sibling is still authoritative. |
| Org & Membership (I-8, membership/tenant rebuild) | stale-if-error, capped at 5 minutes | Valkey reachable + a stale `ae:ctx`/`ae:tenant` pair exists → serve it (§7 row 2). Otherwise → fail-closed, `DENY_SERVICE_UNAVAILABLE` (§7 row 3) — never conflated with an ordinary `Deny`. |
| iam-tender-acl (TAC-4, tender-ACL overlay) | fail-closed, scoped to the overlay only | Timeout/error → `DENY_TENDER_ACL_INSUFFICIENT` for the tender-scoped check only (§7 row 4). Never escalates to `DENY_SERVICE_UNAVAILABLE`, and never denies a non-tender-scoped aspect of the same request. |
| Org & Membership (I-14, MFA-freshness) | fail-closed (judgment call, not in the LLD's §7 table) | Call failure → `DENY_MFA_STALE`, not `DENY_SERVICE_UNAVAILABLE`. Approver-gated actions are exactly the security-sensitive case this service exists to protect, so ambiguity resolves to denial — the client's remedy (re-auth) is the same one a genuinely stale MFA assertion would produce. |

---

## Out of scope

- Any durable schema, migration, or ORM — no live Postgres pool. `platform-pgcommon` is wired for DSN/config/logger/tracer parity with siblings; `NewPool` is not called.
- Publishing events — `platform-events` SNS/outbox config is loaded for env-warning parity; `NewSNSPublisher` / `outbox.ApplySchema` / `NewRunner` are not called.
- JWT issuance, MFA enrollment, realm/tenant provisioning, the Keycloak Admin API.
- A policy-authoring UI — policies are Go code, compiled in, redeployed to change.
- Active session/token revocation (best-effort, owned elsewhere) — this service only bounds the *passive* cutoff via its own cache TTL.
- Rate limiting or quota enforcement — this service only injects `x-plan`/`x-feature-flags` for other components to act on.

---

## See also

- [`.claude/CLAUDE.md`](.claude/CLAUDE.md) — top-level guidance for Claude Code working in this repo.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — layer model, request-flow/cache/event/failure-handling diagrams, key invariants, threat model.
- [`docs/lld/iam-lld-authz-enrichment.md`](docs/lld/iam-lld-authz-enrichment.md) — the Low-Level Design: precedence chain, cache-key table, §7 event-invalidation narrative, §9 `DenyReason`/status table, §16 `AE-#` decision register.
- [`api/asyncapi.yaml`](api/asyncapi.yaml) — the 5-queue/15-event-type consumer contract (see [§ Event architecture](#event-architecture)); also served live at `GET /asyncapi`/`GET /asyncapi.yaml`.
- [`VERSIONING.md`](VERSIONING.md) — SemVer rules for the runtime contract, image tag scheme, maintainer release checklist.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — branch naming, PR checklist, commit style, how to extend each layer.
- [`docs/architecture/`](docs/architecture/) — standalone Mermaid diagram sources.
- [`docs/runbook.md`](docs/runbook.md) — what to do when each alert fires, and the common failure modes behind them.
- `.go-arch-lint.yml` / `.golangci.yml` — the enforced dependency and lint rules.

## License / ownership

Private — BCBP Solutions FZC LLC. Internal platform service; not for external distribution.

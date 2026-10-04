# Renamed and removed metric names

iam-authz-enrichment moved to the Enterprise Platform Observability Standard in three steps. The service has never been deployed to any environment, so no dashboard, alert or stored series depended on the old names. Every old name was **renamed or removed outright, with no compatibility period**. The alerts, PrometheusRule, prometheus-adapter/HPA rule, release health gate and docs in this repo were rewritten in the same change.

## 1. Platform library migration and service prefix (2026-10-02, commit `697cfd6`)

The platform libraries dropped their pre-standard names (platform-gincommon v1.4.0, platform-events/v2, platform-pgcommon/v2). In the same change the service's own metrics took the Tier 3 prefix `iam_authz_enrichment_`.

### Service metrics (`authz_*` → `iam_authz_enrichment_*`)

| Removed name | Replacement |
|---|---|
| `authz_decisions_total` | `iam_authz_enrichment_decisions_total` |
| `authz_deny_reason_total` | `iam_authz_enrichment_deny_reason_total` (label values changed again in step 2) |
| `authz_decision_latency_seconds` | `iam_authz_enrichment_decision_latency_seconds` |
| `authz_cache_lookups_total` | `iam_authz_enrichment_cache_lookups_total` |
| `authz_cache_hits_total` | `iam_authz_enrichment_cache_hits_total` |
| `authz_negative_cache_lookups_total` | `iam_authz_enrichment_negative_cache_lookups_total` |
| `authz_negative_cache_hits_total` | `iam_authz_enrichment_negative_cache_hits_total` |
| `authz_stale_if_error_served_total` | `iam_authz_enrichment_stale_if_error_served_total` |
| `authz_singleflight_coalesced_total` | `iam_authz_enrichment_singleflight_coalesced_total` |
| `authz_i8_call_latency_seconds` | `iam_authz_enrichment_i8_call_latency_seconds` |
| `authz_i12_call_latency_seconds` | `iam_authz_enrichment_i12_call_latency_seconds` |
| `authz_i14_call_latency_seconds` | `iam_authz_enrichment_i14_call_latency_seconds` |
| `authz_decisions_per_second` (prometheus-adapter / HPA) | `iam_authz_enrichment_decisions_per_second` |

### Library metrics this repo queried

| Removed name | Replacement | Where it was used |
|---|---|---|
| `grpc_server_handled_total` | `platform_grpc_server_handled_total` (+ `domain`, `environment`; − `version`) | `release.yml` deploy health gate, now filtered by `domain="iam",service="iam-authz-enrichment"` rather than `job` |
| `sqs_receive_errors_total` | `platform_dependency_request_seconds_count{dependency="sqs",operation="receive_message",outcome="error"}`, which has **no** `queue` label | `cmd/server/receive_watchdog.go` no longer reads a metric at all. Each consumer's SQS client is wrapped to count its own `ReceiveMessage` outcomes. |

The other pre-standard library names (`http_*`, `grpc_*`, `events_*`, `sqs_*`, `pgcommon_*`) were never queried by this repo. Their replacements are listed in the platform-gincommon registry's legacy entries and in each library's `docs/observability/`.

At the same time the identity became mandatory: `domain="iam"` via `Config.Domain` / `OBSERVABILITY_DOMAIN`, and `APP_ENV` restricted to `local, dev, test, staging, prod`. Helm's `APP_ENV` changed from `production` (now rejected) to `prod`.

## 2. Label value and construction corrections (LLD rev 1.30, 2026-10-03)

| Before | After | Why |
|---|---|---|
| `iam_authz_enrichment_deny_reason_total{reason="DENY_SERVICE_UNAVAILABLE"}` (upper-case `DenyReason`) | `{reason="deny_service_unavailable"}`, the `DenyReason` lowercased | The registry's `reason` vocabulary is snake_case (`^[a-z][a-z0-9_]{0,63}$`). Found when the collectors moved onto gincommon's validated constructors. The `DenyReason` on the wire is unchanged. |
| Tier 3 collectors built with `promauto` | `gincommon.NewCounterVec` / `NewCounter` / `NewHistogramVec` (platform-gincommon v1.6.0) | Registry validation of prefix, suffixes and labels at construction; a failure is a startup error, not a panic |
| Label-less `prometheus.Histogram` for the four latency metrics | Label-less `HistogramVec` | gincommon's Tier 3 API has only `NewHistogramVec`. Series names, buckets and exposition are unchanged. |
| `/metrics` via `promhttp.HandlerFor` | `gincommon.MetricsHandler()` | One failing collector no longer blanks the scrape |
| Unbounded `grpc_method` label | Bounded by `grpccommon.RegisterKnownMethods` (`unknown` for anything else) | A probe of an unregistered method can no longer mint a new label value |

## 3. Semantics and alert-shape corrections (LLD rev 1.31, AE-36, 2026-10-04)

No metric was renamed. What changed is what some series count, and how alerts select them:

| Before | After | Why |
|---|---|---|
| `iam_authz_enrichment_decisions_total` / `deny_reason_total` skipped a request with no verified subject (denied in the gRPC adapter) | Counted as `decision="deny"`, `reason="deny_malformed_identity"` (denied inside `Checker.Check`) | Every `Check` call is now exactly one decision; the decision rate is the HPA input |
| `platform_dlq_messages_total` not emitted; malformed bodies deleted and visible only on `platform_messages_failed_total{reason="malformed"}` | `platform_dlq_messages_total{operation="consume", reason="malformed"\|"decode_error"\|"max_receive_count"}`, one per forward | Poison messages are forwarded to the queue's DLQ (AE-36) |
| `environment` from `APP_ENV` only | `APP_ENV`, else `ENVIRONMENT` (trimmed, lowercased) | Same precedence as the platform libraries |
| Alerts selected `job="iam-authz-enrichment"` and returned one unlabelled series | Metric alerts select `domain="iam", service="iam-authz-enrichment"` and aggregate `by (domain, service, environment)`; every alert has a `runbook` annotation | Alerts fire per environment and carry the identity, as in iam-org-membership |

## Querying after the migration

```promql
# Fail-closed denies (was reason="DENY_SERVICE_UNAVAILABLE")
sum by (environment) (rate(iam_authz_enrichment_deny_reason_total{service="iam-authz-enrichment", reason="deny_service_unavailable"}[5m]))

# DLQ forwards by reason (new in step 3)
sum by (environment, reason) (increase(platform_dlq_messages_total{service="iam-authz-enrichment", operation="consume"}[15m]))

# Deny mix
sum by (environment, reason) (rate(iam_authz_enrichment_deny_reason_total{service="iam-authz-enrichment"}[5m]))

# gRPC fault ratio (a deny is grpc_code="OK", so this excludes policy denies)
sum(rate(platform_grpc_server_handled_total{domain="iam", service="iam-authz-enrichment", status_class="5xx"}[5m]))
  /
sum(rate(platform_grpc_server_handled_total{domain="iam", service="iam-authz-enrichment"}[5m]))
```

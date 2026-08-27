# Operator runbook

This service is the Envoy `ext_authz` Policy Decision Point — every request
behind that filter depends on it. This runbook covers the alerts in
`deploy/monitoring/app-alerts.yml` / `deploy/helm/templates/prometheusrule.yaml`
and `deploy/monitoring/dlq-alarms.tf.example`, plus the failure modes those
alerts exist to catch.

## Alert: `AuthzEnrichmentDown` (critical)

No pods scraped as healthy for 2 minutes. This is a platform-wide outage —
every service behind the `ext_authz` filter is affected, not just this one.

1. `kubectl get pods -l app.kubernetes.io/name=iam-authz-enrichment` — are
   pods crash-looping, pending, or just not scraped?
2. If crash-looping: `kubectl logs` the pod. A fail-fast startup error
   (`load config: ...`) means a config value is wrong outside dev — see
   "Startup fails immediately" below.
3. If pending: check node capacity and the pod anti-affinity constraint
   (`deploy/helm/templates/deployment.yaml` requires one pod per node —
   a cluster with fewer nodes than `replicaCount` will stall scheduling).
4. If running but not scraped: check the `ServiceMonitor`/NetworkPolicy —
   `networkPolicy.metricsIngress` must match wherever Prometheus actually
   runs, or the scrape itself is being dropped at the network layer.

## Alert: `AuthzEnrichmentAvailabilitySLOBreach` (critical, SEV-1)

Fleet-wide scrape-success ratio below 99.5% over 10 minutes. Same
investigation as `AuthzEnrichmentDown`, but partial rather than total —
check which specific pods are unhealthy and why.

## Alert: `AuthzEnrichmentDecisionLatencySLOBreach` (warning, SEV-2)

p99 `Check()` latency above 50ms for 5 minutes.

1. Check `authz_i8_call_latency_seconds` / `authz_i12_call_latency_seconds` —
   is Org & Membership itself slow? If so, this is their incident, not this
   service's; `AuthzEnrichmentStaleIfErrorServing` should also be firing.
2. Check the cache hit ratio (`rate(authz_cache_hits_total[5m]) /
   rate(authz_cache_lookups_total[5m])`) — a sudden drop means more
   requests are taking the slow (I-8 call) path. Correlate with a recent
   mass membership/tenant event (bulk import, tenant migration).
3. Check Valkey directly (`valkey-cli --latency` from inside the cluster,
   or the managed Redis/Valkey service's own latency metrics) — a slow
   cache defeats the entire point of caching.
4. No load test has been run against this specific cluster's actual
   hardware/network path — the 50ms threshold is validated against a
   local, single-machine, loopback-network test only (`make load-test`,
   see README § Testing). If this alert fires under otherwise-normal
   conditions on a new cluster, the threshold itself may need revisiting
   for that environment, not just the immediate symptom.

## Alert: `AuthzEnrichmentStaleIfErrorServing` (critical — page directly)

`authz_stale_if_error_served_total` is increasing — §7's stale-if-error path
is active *right now*. This means Valkey is reachable but Org & Membership
is not (or vice versa isn't relevant here — stale-if-error specifically
requires Valkey up + sibling down + a stale entry available).

1. Check Org & Membership's own health/alerts — this is very likely their
   incident manifesting here.
2. This alert is deliberately the earliest signal, ahead of the latency/
   availability SLO alerts — expect it to fire first, and to resolve once
   Org & Membership recovers, without ever tripping the SLO-breach alerts
   if the outage is short enough to stay within the 5-minute stale-if-error
   grace window (hard-capped regardless of config — see
   `internal/config/config.go`).

## Alert: `AuthzEnrichmentServiceUnavailableSpike` (warning)

Sustained `DENY_SERVICE_UNAVAILABLE` — §7 has fail-closed (no stale entry
was available to serve instead), or the tender-ACL overlay's independent
fail-closed rule is firing on TAC-4 failures (formerly I-12 — as of
ADR-0007 Wave 3 Phase 4, this call goes to **iam-tender-acl**, not Org &
Membership; check that service's health first if this alert is isolated to
tender-scoped requests).

1. Same dependency checks as `AuthzEnrichmentStaleIfErrorServing` — this is
   usually the same underlying outage, just past the grace window or with
   no cache warm enough to bridge it (e.g. brand-new tenants/users with no
   existing cache entry at all). For a TAC-4-only spike, check
   **iam-tender-acl** specifically, not Org & Membership.
2. If this is firing with Org & Membership *healthy*, check this service's
   own logs for `"membership rebuild failed, no stale entry available"` —
   the error string in that log line is the actual dial/timeout error, not
   a generic message.

## Alert: `AuthzEnrichmentCacheHitRatioLow` (warning)

ae:ctx/ae:tenant hit ratio below 50% for 15 minutes. Check for a recent bulk
membership/tenant event, a TTL misconfiguration
(`AE_CTX_TTL`/`AE_CTX_JITTER`), or Valkey eviction pressure (check Valkey's
own `evicted_keys` metric / memory usage — a cache that's evicting under
memory pressure defeats jittered TTLs entirely).

## CloudWatch alarm: a `*-authz-q-dlq` queue is non-empty

A message failed all 5 delivery attempts (SQS-native redrive — no
application code is involved in this decision, see
`internal/adapter/inbound/consumer`'s package doc comment). This is a
**correctness gap, not an availability one** — the eviction that message
was supposed to trigger never happened, meaning some cache entry may now be
stale beyond its intended TTL.

1. `awslocal sqs receive-message --queue-url <dlq-url>` (or the real AWS
   CLI in production) to read the message body and see what event/tenant
   it was for.
2. Check this service's logs around the time of the original delivery
   attempts for the actual handler error (`internal/usecase/invalidate.go`'s
   `Handle*` methods log on failure).
3. Once the root cause is fixed, manually replay the message (there is no
   automated DLQ replay mechanism — deliberately, per §5) by re-sending an
   equivalent event to the primary queue, or manually evicting the
   affected cache key via `valkey-cli DEL <key>` if the fix doesn't require
   re-processing the original event content.
4. Delete the message from the DLQ once resolved — it will not expire on
   its own within any timeframe you should wait for
   (`MessageRetentionPeriod` is measured in days).

## Startup fails immediately with `load config: ORG_MEMBERSHIP_BASE_URL ...`

The deployment left `ORG_MEMBERSHIP_BASE_URL` at its local-dev default
outside `APP_ENV=dev` — `internal/config/config.go` fails fast on this
rather than starting and silently failing every non-cache-hit request. Set
`ORG_MEMBERSHIP_BASE_URL` to the real Org & Membership service address for
this environment.

## Log line: `no tenant-resolution path configured` (warning, at startup)

Neither `SHARED_REALM_ISSUER` nor `REALM_TENANT_MAP_SEED` resolve any
tenant — every request will get `DENY_MALFORMED_IDENTITY` until one of
them is populated (a `TenantConverted`/`TenantRealmReady` event will
populate the realm map at runtime once one arrives; this warning is
expected and harmless on a genuinely brand-new platform with zero tenants
yet).

## Recurring log noise: `traces export: exporter export timeout`

Benign — `OTEL_EXPORTER_OTLP_ENDPOINT` has no collector actually listening
(defaults to `localhost:4317`). Spans are dropped, nothing else is
affected. Set `OTEL_EXPORTER_OTLP_ENDPOINT` to a real collector to silence
this, or accept the noise. See `.env-example`'s OTel section for the
related `OTEL_EXPORTER_OTLP_INSECURE` gotcha (it depends on the *raw*
`APP_ENV` process env var, not this service's own config default).

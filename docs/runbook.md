# Operator runbook

This service is the Envoy `ext_authz` Policy Decision Point — every request
behind that filter depends on it. This runbook covers the alerts in
`deploy/monitoring/app-alerts.yml` / `deploy/helm/templates/prometheusrule.yaml`
and `deploy/monitoring/dlq-alarms.tf.example`, plus the failure modes those
alerts exist to catch.

Short per-alert Meaning/Triage/Mitigate entries, in the platform's standard
format, are in [`observability/runbooks.md`](observability/runbooks.md).
Metric definitions and label values are in
[`observability/metric-registry.md`](observability/metric-registry.md).

## Go-live checklist

Items the code and chart cannot settle on their own. Each has to be done, or
explicitly signed off, before production traffic.

**Infrastructure (platform Terraform / cluster):**

- [ ] IRSA role has `deploy/iam/policy.json` applied, including the
      `ForwardPoisonMessagesToDLQ` statement (`GetQueueUrl`, `GetQueueAttributes`,
      `SendMessage` on the five `-dlq` queues). Without it DLQ forwards fail
      (SQS redrive takes over) and `platform_dlq_depth` logs permission errors.
- [ ] All five queues have a RedrivePolicy (`maxReceiveCount=5`) — a consumer
      refuses to start without one, and the pod restarts.
- [ ] Encryption in transit to the gRPC port: confirm the mesh / CNI provides
      mTLS and set the repo variable `MESH_PROVIDES_MTLS=true` (release.yml), or
      enable `grpcTLS` in values. The chart refuses to render `APP_ENV=prod`
      otherwise.
- [ ] Production secrets come from `existingSecret` (External Secrets /
      CSI). With IRSA, the AWS key entries in that Secret may be empty.
- [ ] `VALKEY_URL` uses `rediss://` (TLS in transit, with AUTH if the cache
      requires it); a malformed URL now fails startup.
- [ ] The cluster spans the zones `topologySpread` expects (set
      `zoneWhenUnsatisfiable: ScheduleAnyway` on a single-zone cluster).
- [ ] The Envoy ext_authz filter matches README § Envoy configuration sketch:
      `failure_mode_allow: false`, `timeout: 0.25s`, the jwt_authn metadata
      namespace, and `/tenders/{id}` path segments on tender-scoped routes.
- [ ] `serviceMonitor.enabled: true` with the Prometheus operator's selector
      labels, the prometheus-adapter rule installed, and the CloudWatch DLQ
      alarms (`deploy/monitoring/dlq-alarms.tf.example`) applied.

**Dependencies to track:**

- [ ] Upgrade `google.golang.org/grpc` to v1.85.0 when released and remove
      GO-2026-6443 from `.github/govulncheck-allow.txt` (the exception expires
      2026-11-15 and CI fails after that).
- [ ] Load-test the target cluster (`make load-test`): the 50ms p99 alert and
      the 15ms budget were validated on loopback only.

**Risk acceptances that need an owner's sign-off (LLD §16):**

- [ ] AE-17 — `TenantOffboarded` is not consumed. **Its rationale ("every
      cache key is TTL-bound to 5–60s") is wrong for two keys:** `ae:realm`
      and `ae:restricted` are written with no TTL (`valkey/cache.go`
      `SetRealm`/`SetRestricted`), so an offboarded tenant's realm mapping and
      tender-restriction facts stay in Valkey indefinitely. They hold IDs, not
      personal data, but a reused realm issuer would still resolve to the old
      tenant. Either accept that explicitly, or subscribe to
      `TenantOffboarded` and delete the tenant's `ae:realm` / `ae:restricted`
      keys (needs the producer's event contract).
- [ ] §8.5.1 — `ae:restricted` has no TTL: a lost or unreplayed
      `TenderRestricted`/`TenderUnrestricted` leaves the overlay state wrong
      until a later event or manual fix.
- [ ] §7 — `/readyz` reports process startup only, not Valkey or sibling
      health (failures degrade to stale-if-error / fail-closed instead).
- [ ] AE-37 — cache-miss decisions can take up to the siblings' own latency
      (≤ 250ms) instead of being cut off at 10ms.

## Alert: `AuthzEnrichmentDown` (critical)

No pods scraped as healthy for 2 minutes. This is a platform-wide outage —
every service behind the `ext_authz` filter is affected, not just this one.

1. `kubectl get pods -l app.kubernetes.io/name=iam-authz-enrichment` — are
   pods crash-looping, pending, or just not scraped?
2. If crash-looping: `kubectl logs` the pod. A fail-fast startup error
   (`load config: ...`) means a config value is wrong outside dev — see
   "Startup fails immediately" below.
3. If pending: check node capacity and the zone spread
   (`topologySpread` in values: pods must spread evenly across zones, so a
   zone with no schedulable capacity blocks new pods — use
   `zoneWhenUnsatisfiable: ScheduleAnyway` on a single-zone cluster).
4. If running but not scraped: check the `ServiceMonitor`/NetworkPolicy —
   `networkPolicy.metricsIngress` must match wherever Prometheus actually
   runs, or the scrape itself is being dropped at the network layer.

## Alert: `AuthzEnrichmentAvailabilitySLOBreach` (critical, SEV-1)

Fleet-wide scrape-success ratio below 99.5% over 10 minutes. Same
investigation as `AuthzEnrichmentDown`, but partial rather than total —
check which specific pods are unhealthy and why.

## Alert: `AuthzEnrichmentDecisionLatencySLOBreach` (warning, SEV-2)

p99 `Check()` latency above 50ms for 5 minutes.

1. Check `iam_authz_enrichment_i8_call_latency_seconds` / `iam_authz_enrichment_i12_call_latency_seconds` —
   is Org & Membership itself slow? If so, this is their incident, not this
   service's; `AuthzEnrichmentStaleIfErrorServing` should also be firing.
2. Check the cache hit ratio (`rate(iam_authz_enrichment_cache_hits_total[5m]) /
   rate(iam_authz_enrichment_cache_lookups_total[5m])`) — a sudden drop means more
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

`iam_authz_enrichment_stale_if_error_served_total` is increasing — §7's stale-if-error path
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

## TAC-4 outage (`iam-tender-acl` dependency down)

A `iam-tender-acl` outage is **not** surfaced as `DENY_SERVICE_UNAVAILABLE` —
it fails closed with `DENY_TENDER_ACL_INSUFFICIENT` instead (§7 row 4: the
tender-ACL overlay fails closed for that overlay only, never escalates to a
full-service deny). On-call cannot distinguish a TAC-4 service outage from a
legitimate access denial by looking at `iam_authz_enrichment_deny_reason_total`
alone. Use the following signals to identify a TAC-4 outage specifically:

0. `iam_authz_enrichment_tac4_errors_total` — counts only TAC-4 call failures, never policy denials; a nonzero rate fires `AuthzEnrichmentTAC4ErrorSpike` (see `docs/observability/runbooks.md`).
1. `iam_authz_enrichment_i12_call_latency_seconds` — a sudden spike in latency or a gap (no data) indicates TAC-4 is slow or unreachable.
2. `iam_authz_enrichment_deny_reason_total{reason="deny_tender_acl_insufficient"}` — an elevated rate that is **not** explained by expected access-control denials. Cross-check with TAC-4 call latency above to distinguish "real denials" from "overlay failed closed due to outage".
3. `iam-tender-acl`'s own health/alerts — this is almost certainly their incident manifesting in this service.
4. Logs from this service: look for `"tender acl rebuild"` errors with non-404 causes.

**Note on HTTP 400 vs 503:** a TAC-4 400 (invalid UUID sent by this service) maps to `ErrNotFound` and does NOT activate the §7 stale-if-error path — if you see 400s, the issue is a malformed `tender_id` being sent (check `requestfacts.go`'s `tenderIDFromPath()` for the URL path this service is parsing), not a TAC-4 outage.

**During a TAC-4 outage:** only tender-scoped requests (those whose URL path matches `/tenders/:id`) are affected. Non-tender requests continue to be decided normally. The blast radius is bounded to the overlay step.

## Alert: `AuthzEnrichmentServiceUnavailableSpike` (warning)

Sustained `DENY_SERVICE_UNAVAILABLE` — §7 has fail-closed on an Org &
Membership or Valkey failure (no stale entry was available to serve
instead). TAC-4 (iam-tender-acl) failures never produce this reason — see
the TAC-4 outage section above and `AuthzEnrichmentTAC4ErrorSpike`.

1. Same dependency checks as `AuthzEnrichmentStaleIfErrorServing` — this is
   usually the same underlying outage, just past the grace window or with
   no cache warm enough to bridge it (e.g. brand-new tenants/users with no
   existing cache entry at all).
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

A message was forwarded to the queue's DLQ (LLD §16 AE-36): either it failed
4 deliveries and was forwarded on its 5th, or its body could not be parsed or
Glue-decoded and was forwarded on first receipt (SQS's own redrive is the
backstop if a forward failed). The DLQ copy keeps the original body and
attributes plus `DLQReason`, `OriginalQueue` and `FailedAt`. This is a
**correctness gap, not an availability one** — the eviction that message
was supposed to trigger never happened, meaning some cache entry may now be
stale beyond its intended TTL.

1. `awslocal sqs receive-message --queue-url <dlq-url>` (or the real AWS
   CLI in production) to read the message body and see what event/tenant
   it was for.
2. Check this service's logs around the time of the original delivery
   attempts for the actual handler error (`internal/usecase/invalidate.go`'s
   `Handle*` methods log on failure). The 5th delivery also logs
   `message exhausted retries, moving it to the DLQ` (with
   `queue`/`event_id`/`event_type`/`tenant_id`) — the first signal, ahead of
   this alarm. `DLQReason=malformed` or `decode_error` means the body never
   reached a handler. A `glue decode codec:` error means the producer sent a malformed or
   compressed Glue frame (compression is not supported); a JSON decode
   error on a Glue-encoded event can no longer happen for a well-formed
   frame (platform-events `GlueDecodeCodec`, LLD AE-35).
3. Once the root cause is fixed, manually replay the message (there is no
   automated DLQ replay mechanism — deliberately, per §5) by re-sending an
   equivalent event to the primary queue, or manually evicting the
   affected cache key via `valkey-cli DEL <key>` if the fix doesn't require
   re-processing the original event content.
4. Delete the message from the DLQ once resolved — it will not expire on
   its own within any timeframe you should wait for
   (`MessageRetentionPeriod` is measured in days).

## Log line: `sqs receive-error watchdog: consumer appears stuck` (pod restart)

One of the 5 SQS consumers has failed every `ReceiveMessage` call for
several minutes straight (`cmd/server/receive_watchdog.go` — `staleAfter`
consecutive polls, default 6 × 30s ≈ 3 minutes, with no successful receive
in between). This exists because `platform-events`' consumer loop never
returns an error for a persistently failing receive loop — it retries
forever internally and only logs `sqs: receive message failed` — so
without this watchdog a broken consumer would silently stop evicting that
queue's cache entries forever while `/healthz`/`/readyz` stayed green.

The watchdog pushes to `fatalErr`, which shuts the process down so
the orchestrator restarts the pod (same log line as
`AuthzEnrichmentDown`/`AuthzEnrichmentAvailabilitySLOBreach` above). A
plain restart does **not** fix the underlying cause — it only restores
visibility (the alerts above will fire again immediately if the cause is
still present) and forces a fresh IAM/queue-config resolution.

1. Check the `queue` field on the log line to identify which of the 5
   queues is affected (the watchdog tracks each consumer's own
   `ReceiveMessage` results, so the log line is the per-queue signal). The
   service-level metric is
   `sum by (domain, service, environment) (rate(platform_dependency_request_seconds_count{service="iam-authz-enrichment",dependency="sqs",operation="receive_message",outcome="error"}[5m]))`
   — it has **no** `queue` label, so it confirms receive errors but not
   which queue (registry status: proposed). The pod's
   `sqs: receive message failed` error logs carry the AWS error.
2. Most likely cause: the queue was deleted, or this pod's IAM role/policy
   no longer grants `sqs:ReceiveMessage` on it (a permissions change is not
   fixed by restarting — fix the permission/queue, not the pod).
3. If the pod keeps crash-looping on this after the underlying cause is
   fixed, confirm `AWS_REGION`/`AWS_ENDPOINT_URL` and the affected
   `*_AUTHZ_QUEUE_URL` are still correct for this environment.

## Log line: `grpc server exited` / `http server exited` / `metrics server exited`

One of the three servers `cmd/server/main.go` runs (gRPC ext_authz, HTTP
health/readiness, or `/metrics`) exited unexpectedly — not via this
process's own deliberate shutdown. This is immediately followed by `fatal
error — shutting down so the orchestrator restarts this pod`: unlike a
stuck SQS consumer (which only degrades one fact class to stale-per-TTL),
a dead gRPC server means **100% of Envoy's ext_authz traffic is failing**,
so this always triggers an immediate restart rather than a lengthy
detection window — see LLD §16 AE-28 for why this needed fixing at all
(`livenessProbe`/`readinessProbe` are `httpGet`-only, §12/`values.yaml`,
so they cannot see a dead gRPC server on their own).

1. Check which server exited (`grpc`/`http`/`metrics` in the log line) and
   the accompanying `error` field — this is almost always the actual root
   cause (a listener-level failure, not application logic).
2. If the pod keeps crash-looping on this immediately after restart, check
   for a port conflict, a resource limit being hit (file descriptors), or
   a `GRPC_TLS_CERT_FILE`/`_KEY_FILE` pointing at a certificate that
   rotated to something the running pod can no longer read.
3. A single occurrence with no recurrence is expected on some
   underlying-infrastructure blips (e.g. a CNI-level listener reset) — the
   restart itself is the fix in that case.

## Startup fails immediately with `load config: ORG_MEMBERSHIP_BASE_URL ...`

The deployment left `ORG_MEMBERSHIP_BASE_URL` at its local-dev default
outside `APP_ENV=dev` — `internal/config/config.go` fails fast on this
rather than starting and silently failing every non-cache-hit request. Set
`ORG_MEMBERSHIP_BASE_URL` to the real Org & Membership service address for
this environment. The same applies to `TENDER_ACL_BASE_URL`. The Helm chart
defaults both to the IAM convention
(`http://iam-org-membership.iam.svc.cluster.local:8080`,
`http://iam-tender-acl.iam.svc.cluster.local:8080`), so this only happens when
a values override blanks them.

## I-8 / TAC-4 calls time out although both siblings are healthy

Check the NetworkPolicy path in both directions: this chart's
`networkPolicy.upstreamEgress` must match each sibling's real pod labels and
namespace (`app.kubernetes.io/name: iam-org-membership` / `tender-acl` in
`iam`), and iam-tender-acl's `networkPolicy.internalCallerPodSelectors` must
list `app.kubernetes.io/name: iam-authz-enrichment`. A NetworkPolicy drop
looks like a timeout, not a connection refusal.

## Startup fails immediately with `... and ... are both set to the same queue URL`

Two of the five `*_AUTHZ_QUEUE_URL` env vars were set to an identical
value — almost always a copy-paste mistake in the deployment config. Left
uncaught, this would also silently corrupt the receive-error watchdog's
per-URL streak tracking above (two aliases racing to update/reset the same
counter every poll), permanently masking a stuck consumer on that URL.
Fix the duplicated env var to point at its own distinct queue.

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

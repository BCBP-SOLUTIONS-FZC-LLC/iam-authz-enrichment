# Runbooks: iam-authz-enrichment alerts

Runbooks for every alert in [`deploy/monitoring/app-alerts.yml`](../../deploy/monitoring/app-alerts.yml), the Helm [`PrometheusRule`](../../deploy/helm/templates/prometheusrule.yaml) (the same rules) and the CloudWatch DLQ alarms in [`deploy/monitoring/dlq-alarms.tf.example`](../../deploy/monitoring/dlq-alarms.tf.example). Each heading is the alert name, and the alert's `runbook` annotation points to the same entry. Every metric alert carries `domain`, `service` and `environment`. Longer walkthroughs, and the failure modes that surface as log lines rather than alerts, are in [`../runbook.md`](../runbook.md). Platform-level alerts on the libraries' own metrics are documented in platform-gincommon's `docs/observability/runbooks.md`.

This service is Envoy's `ext_authz` Policy Decision Point, so every request behind that filter depends on it. Treat any availability alert as platform-wide.

Common starting points:

- Rollouts: `count by (version) (platform_build_info{service="iam-authz-enrichment",environment="$environment"})`
- Traffic and faults: `sum by (grpc_code) (rate(platform_grpc_server_handled_total{service="iam-authz-enrichment"}[5m]))`. A deny is `grpc_code="OK"`, so look at `iam_authz_enrichment_deny_reason_total` for denies.
- Logs (Loki): `{service="iam-authz-enrichment"} | json`, then follow `trace_id` into Tempo. A decision trace has `authz.lookup_cache`, `authz.i8_call`, `authz.i12_call` and `authz.mfa_freshness_call` children.
- Readiness: `GET /readyz` reports process startup only, **not** dependency health (§7). A green `/readyz` says nothing about Valkey or the siblings.

## Availability

### AuthzEnrichmentDown

**Meaning.** No pod has been scraped as healthy for 2 minutes. Every request behind the `ext_authz` filter is affected.

**Triage.**
1. `kubectl get pods -l app.kubernetes.io/name=iam-authz-enrichment`. Check whether pods are crash-looping, pending, or running but not scraped.
2. Crash loop: startup refuses bad configuration by design. Look for `load config:` with a dev-default `ORG_MEMBERSHIP_BASE_URL`/`TENDER_ACL_BASE_URL`, a blank or duplicate `*_AUTHZ_QUEUE_URL`, a non-positive gRPC or concurrency value, or an invalid `APP_ENV`. Also check for `init business metrics` / `init tracing` errors. The log line names the cause.
3. A pod that keeps restarting with `fatal error — shutting down` hit the shared `fatalErr` path: a dead gRPC/HTTP/metrics server or a stuck SQS consumer. See [`../runbook.md`](../runbook.md).
4. Running but not scraped: `networkPolicy.metricsIngress` must match where Prometheus runs, and `serviceMonitor.enabled` must be true.

**Mitigate.** Roll back the last deploy, or fix the named configuration.

### AuthzEnrichmentReplicasMissing

**Meaning.** Fewer than 2 replicas are healthy (PDB `minAvailable: 2`; HPA `minReplicas: 5`). One more disruption risks an outage, and node drains are blocked.

**Triage.** As for `AuthzEnrichmentDown`, per pod. Also check node capacity and zone spread: replicas must spread evenly across zones (`topologySpread`), so a zone with no capacity leaves pods Pending.

### AuthzEnrichmentAvailabilitySLOBreach

**Meaning.** SEV-1: the fleet-wide scrape-success ratio has been below 99.5% over 10 minutes (LLD §11.1). This is a partial outage. Some pods are unhealthy or flapping.

**Triage.** As for `AuthzEnrichmentDown`. Find which pods are failing and why, starting with restarts and OOM kills (`kubectl describe pod`).

## Latency

### AuthzEnrichmentDecisionLatencySLOBreach

**Meaning.** SEV-2: p99 of `iam_authz_enrichment_decision_latency_seconds` has been above 50 ms for 5 minutes. The design budget is 15 ms (LLD §11.1).

**Triage.**
1. Siblings: `histogram_quantile(0.99, sum by (le) (rate(iam_authz_enrichment_i8_call_latency_seconds_bucket[5m])))`, then the same for `i12` (iam-tender-acl TAC-4) and `i14`. If one is slow, it is likely that service's incident, and `AuthzEnrichmentStaleIfErrorServing` may also fire.
2. Cache: a falling hit ratio (`AuthzEnrichmentCacheHitRatioLow`) pushes requests onto the I-8 path. Look for a recent bulk membership or tenant event.
3. Valkey: round-trip latency (`valkey-cli --latency`, or the managed service's metrics). The default `VALKEY_READ_TIMEOUT` is 10 ms.
4. Saturation: `platform_grpc_server_inflight_requests` per pod against `GRPC_MAX_CONCURRENT_STREAMS`, plus CPU throttling.

**Mitigate.** Scale out if saturated, or restore the slow dependency. The 50 ms threshold has only been validated on a local loopback load test (`make load-test`). On a new cluster, confirm it is realistic before tuning anything else.

## Dependency health

### AuthzEnrichmentStaleIfErrorServing

**Meaning.** Page directly. `iam_authz_enrichment_stale_if_error_served_total` is increasing, so §7's stale-if-error path is active: Valkey is up, a sibling (usually Org & Membership) is failing, and expired `ae:ctx` entries are being served. This is the earliest outage signal, ahead of the SLO alerts.

**Triage.** Check Org & Membership's health and alerts first. Then check this pod's `i8` latency and logs for the dial or timeout error. The grace window is capped at 5 minutes (`internal/config/config.go`).

**Mitigate.** Restore the sibling. The alert resolves on its own when I-8 recovers. If the outage outlasts the window, `AuthzEnrichmentServiceUnavailableSpike` follows.

### AuthzEnrichmentServiceUnavailableSpike

**Meaning.** `iam_authz_enrichment_deny_reason_total{reason="deny_service_unavailable"}` has been sustained for 5 minutes. §7 has failed closed on an Org & Membership or Valkey failure with no stale entry to serve. TAC-4 (iam-tender-acl) failures never produce this reason — they fail closed to `DENY_TENDER_ACL_INSUFFICIENT` and fire `AuthzEnrichmentTAC4ErrorSpike`.

**Triage.**
1. Run the same checks as `AuthzEnrichmentStaleIfErrorServing`. New tenants or users with no cache entry fail closed immediately.
2. Siblings healthy but still failing: check the NetworkPolicy path (`networkPolicy.upstreamEgress`). A dropped connection looks like a timeout. Then search the logs for `membership rebuild failed, no stale entry available`.

**Mitigate.** Restore the dependency or the network path.

### AuthzEnrichmentTAC4ErrorSpike

**Meaning.** `iam_authz_enrichment_tac4_errors_total` is increasing: `GetTenderACL` (TAC-4) calls to iam-tender-acl are failing, and the tender-ACL overlay is failing closed with `DENY_TENDER_ACL_INSUFFICIENT` on every restricted-tender request (§7 row 4). Legitimate access-control denials don't increment this counter, so a nonzero rate is a dependency problem, not a policy one.

**Triage.**
1. Check iam-tender-acl's health and alerts, and this pod's `iam_authz_enrichment_i12_call_latency_seconds` — a p99 pinned at `TENDER_ACL_TIMEOUT` means timeouts, not errors.
2. iam-tender-acl healthy: check the NetworkPolicy path in both directions (`networkPolicy.upstreamEgress`, and iam-tender-acl's `internalCallerPodSelectors`), and that `TENDER_ACL_BASE_URL` points at the right service.

**Mitigate.** Restore iam-tender-acl or the network path. Don't raise `TENDER_ACL_TIMEOUT` below iam-tender-acl's own p99 target (AE-37) to mask it.

## Cache

### AuthzEnrichmentCacheHitRatioLow

**Meaning.** The `ae:ctx`/`ae:tenant` hit ratio has been below 50% for 15 minutes (target ~95%, HLD §8.3). More requests take the I-8 path, raising latency and Org & Membership load.

**Triage.** Check for a recent mass eviction (bulk membership or tenant event, visible as a spike in `platform_messages_processed_total` on `membership-authz-q`/`tenant-authz-q`), a TTL misconfiguration (`AE_CTX_TTL`, `AE_CTX_JITTER`), or Valkey memory pressure (`evicted_keys`).

**Mitigate.** Size Valkey for the working set, or correct the TTL. A short dip after a bulk event recovers on its own.

## Events

### AuthzEnrichmentDLQForwards

**Meaning.** platform-events forwarded one or more event messages to their queue's DLQ in the last 15 minutes (`platform_dlq_messages_total{operation="consume"}`, LLD §16 AE-36). Each one is an eviction that was never applied, so some cache entries may be stale beyond their TTL. For `tender-authz-q` (`ae:restricted`, no TTL) they stay wrong until replayed.

**Triage.** The `reason` label says why:
- `malformed`: the body is not a valid envelope. A producer is publishing something unparseable. The library logs the message ID and `body_sha256`, never the body.
- `decode_error`: a Glue frame failed to decode (a compressed or non-JSON payload; `glue decode codec:` in the logs).
- `max_receive_count`: a handler failed four deliveries and the message was forwarded on the 5th. The 5th delivery logged `message exhausted retries, moving it to the DLQ` with `queue`, `event_id`, `event_type` and `tenant_id`; the earlier handler errors name the cause (usually Valkey).

Read the DLQ copy (`aws sqs receive-message --queue-url <dlq-url> --message-attribute-names All`). Its `DLQReason`, `OriginalQueue` and `FailedAt` attributes say where it came from, and the body is the original, so it can be redriven unchanged.

**Mitigate.** Fix the producer or the failing dependency, then redrive the message to its source queue, or evict the affected key with `valkey-cli DEL`. Delete the DLQ copy once resolved. There is no automated replay (§5).

### AuthzEnrichmentEventFailureRateHigh

**Meaning.** More than half of the deliveries on one queue have failed for 10 minutes (`platform_messages_failed_total / platform_messages_received_total`). Evictions for that queue are being retried and will soon be forwarded to the DLQ.

**Triage.** `sum by (queue, reason) (rate(platform_messages_failed_total{service="iam-authz-enrichment"}[10m]))`. `handler_error` is almost always Valkey (check `EvictMembershipContext`/`EvictTenderACL` errors in the logs); `malformed`/`decode_error` is a producer problem, as in `AuthzEnrichmentDLQForwards`.

**Mitigate.** Restore Valkey, or fix the producer.

### `iam-authz-enrichment-<queue>-dlq-nonempty` (CloudWatch)

**Meaning.** A message is sitting in a queue's DLQ. `AuthzEnrichmentDLQForwards` says one arrived; this says it is still there. It got there by a platform-events forward or, if a forward failed, by SQS's own redrive after the 5th receive.

**Triage and mitigation.** As for `AuthzEnrichmentDLQForwards`. Never discard a DLQ message without understanding which eviction it carried.

# Monitoring for iam-authz-enrichment

What every metric means, its labels and tier, and how the rules below map to SLOs: [`docs/observability/`](../../docs/observability/README.md). Per-alert runbooks: [`docs/observability/runbooks.md`](../../docs/observability/runbooks.md).

| File | What it covers | Deploy mechanism |
|---|---|---|
| `app-alerts.yml` | Prometheus alerting rules — decision-latency/availability SLO breaches (LLD §11.1), stale-if-error serving, dependency-failure deny spikes, cache hit ratio, DLQ forwards and per-queue event failure rate. **The source of truth**: `deploy/helm/templates/prometheusrule.yaml` is generated from it (`make prometheusrule`; CI fails on drift). Unit-tested by `tests/app-alerts.test.yml` (`make rules-test`). | `kubectl apply` via PrometheusRule CRD (Helm) or a Prometheus `--rule-files` directory |
| `prometheus-adapter-rule.yaml` | Maps `iam_authz_enrichment_decisions_total` to the Custom Metrics API so the HPA can scale on decision rate (`autoscaling.targetDecisionsPerSecondPerReplica` in `deploy/helm/values.yaml`). Optional — HPA falls back to CPU/memory alone without it. | Merge into the cluster's `prometheus-adapter` ConfigMap |
| `dlq-alarms.tf.example` | CloudWatch alarms on the five §5 dead-letter queues. Covers a gap Prometheus can't: SQS queue depth is a CloudWatch-native metric, and no application code ever reads a `-dlq` queue (`ARCHITECTURE.md`'s "DLQ target is infra-owned" invariant): `platform_dlq_messages_total` counts forwards, but only this alarm says a message is still sitting there. | Illustrative Terraform — platform Terraform owns the real resource, same convention as `deploy/iam/policy.tf.example` |

None of these three are optional in the sense of "skip them" — `app-alerts.yml`/the PrometheusRule requires `serviceMonitor.enabled: true` in the Helm chart to have anything to alert on (see that value's own comment), and the DLQ alarms are the only alerting this service has for a real, silent failure mode. Set them up before relying on this service in production.

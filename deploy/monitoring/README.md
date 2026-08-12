# Monitoring for iam-authz-enrichment

| File | What it covers | Deploy mechanism |
|---|---|---|
| `app-alerts.yml` | Prometheus alerting rules — decision-latency/availability SLO breaches (thresholds match `ARCHITECTURE.md` §10), stale-if-error serving, dependency-failure deny spikes, cache hit ratio. Same rules as `deploy/helm/templates/prometheusrule.yaml`, in plain `--rule-files` form for non-Helm Prometheus setups. | `kubectl apply` via PrometheusRule CRD (Helm) or a Prometheus `--rule-files` directory |
| `prometheus-adapter-rule.yaml` | Maps `authz_decisions_total` to the Custom Metrics API so the HPA can scale on decision rate (`autoscaling.targetDecisionsPerSecondPerReplica` in `deploy/helm/values.yaml`). Optional — HPA falls back to CPU/memory alone without it. | Merge into the cluster's `prometheus-adapter` ConfigMap |
| `dlq-alarms.tf.example` | CloudWatch alarms on the five §5 dead-letter queues. Covers a gap Prometheus can't: SQS queue depth is a CloudWatch-native metric, and DLQ routing is entirely SQS-native (no application code ever reads a `-dlq` queue — see `ARCHITECTURE.md`'s "DLQ routing is infra-only" invariant), so without this a message stuck in a DLQ is completely unmonitored. | Illustrative Terraform — platform Terraform owns the real resource, same convention as `deploy/iam/policy.tf.example` |

None of these three are optional in the sense of "skip them" — `app-alerts.yml`/the PrometheusRule requires `serviceMonitor.enabled: true` in the Helm chart to have anything to alert on (see that value's own comment), and the DLQ alarms are the only alerting this service has for a real, silent failure mode. Set them up before relying on this service in production.

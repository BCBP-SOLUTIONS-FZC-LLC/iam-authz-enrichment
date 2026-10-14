// Package metrics is the Prometheus-backed implementation of
// usecase.Recorder (§10). Cross-cutting instrumentation, not a business
// adapter — imported by both the usecase layer (via the interface) and
// cmd/server (composition root).
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/gincommon"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// Recorder implements usecase.Recorder against gincommon's Prometheus
// registerer (the same registry cmd/server's /metrics listener scrapes
// via metricsScrapeHandler / gincommon.MetricsRegisterer()).
//
// iam_authz_enrichment_cache_hit_ratio and iam_authz_enrichment_negative_cache_hit_ratio
// (§10) are each exposed as a hits/lookups counter pair rather than a single
// ratio gauge — computing a ratio metric server-side and exposing it as a gauge
// is a well-known Prometheus anti-pattern (it can't be aggregated correctly
// across replicas or time windows); `rate(iam_authz_enrichment_cache_hits_total[5m]) /
// rate(iam_authz_enrichment_cache_lookups_total[5m])` in PromQL is the correct
// way to get the ratio the doc names.
type Recorder struct {
	decisionsTotal      *prometheus.CounterVec
	denyReasonTotal     *prometheus.CounterVec
	decisionLatency     prometheus.Histogram
	cacheLookups        prometheus.Counter
	cacheHits           prometheus.Counter
	negCacheLookups     prometheus.Counter
	negCacheHits        prometheus.Counter
	staleServedTotal    prometheus.Counter
	sfCoalescedTotal    prometheus.Counter
	dependencyLatency   *prometheus.HistogramVec
	tac4ErrorsTotal     prometheus.Counter
	evictionErrorsTotal *prometheus.CounterVec
}

// New builds and registers all iam_authz_enrichment_* metrics on reg — the same
// registry cmd/server's dedicated /metrics listener scrapes via
// gincommon.MetricsRegisterer(). reg is optional (variadic so every existing
// zero-arg call site keeps compiling) and defaults to
// prometheus.DefaultRegisterer; cmd/server passes gincommon.MetricsRegisterer()
// AFTER ObservabilityMiddlewares has run, so these collectors land in the same
// registry and pick up the same {service, version} const labels as
// platform-gincommon's own HTTP/gRPC series (same convention as
// iam-org-membership / iam-user-profile).
func New(reg ...prometheus.Registerer) *Recorder {
	registerer := prometheus.DefaultRegisterer
	if len(reg) > 0 && reg[0] != nil {
		registerer = reg[0]
	}
	return newRecorder(registerer)
}

// gincommonLabels returns a copy of gincommon's {service, version} const
// labels so iam_authz_enrichment_* collectors scrape on the same registry and
// labels as HTTP/gRPC interceptor metrics. Returns nil when
// ObservabilityMiddlewares has not run yet, matching prometheus's "no const
// labels" zero value so unit tests that never bootstrap gincommon still
// register cleanly.
func gincommonLabels() prometheus.Labels {
	return constLabelsOrNil(gincommon.MetricsConstLabels())
}

func constLabelsOrNil(labels prometheus.Labels) prometheus.Labels {
	if len(labels) == 0 {
		return nil
	}
	return labels
}

// newRecorder builds and registers all iam_authz_enrichment_* metrics on reg.
// Factored out from New() so tests can pass an isolated prometheus.NewRegistry()
// instead of colliding on the process-wide default registry when multiple tests
// (or test files) each want their own Recorder.
func newRecorder(reg prometheus.Registerer) *Recorder {
	f := promauto.With(reg)
	labels := gincommonLabels()
	return &Recorder{
		decisionsTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name:        "iam_authz_enrichment_decisions_total",
			Help:        "Total ext_authz decisions, by decision (allow/deny).",
			ConstLabels: labels,
		}, []string{"decision"}),
		denyReasonTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name:        "iam_authz_enrichment_deny_reasons_total",
			Help:        "Total deny decisions, by DenyReason.",
			ConstLabels: labels,
		}, []string{"reason"}),
		decisionLatency: f.NewHistogram(prometheus.HistogramOpts{
			Name:        "iam_authz_enrichment_decision_latency_seconds",
			Help:        "End-to-end Check() decision latency.",
			Buckets:     prometheus.ExponentialBuckets(0.0005, 2, 16), // 0.5ms .. ~16s
			ConstLabels: labels,
		}),
		cacheLookups: f.NewCounter(prometheus.CounterOpts{
			Name:        "iam_authz_enrichment_cache_lookups_total",
			Help:        "Total ae:ctx/ae:tenant lookups. Divide iam_authz_enrichment_cache_hits_total by this for the hit ratio.",
			ConstLabels: labels,
		}),
		cacheHits: f.NewCounter(prometheus.CounterOpts{
			Name:        "iam_authz_enrichment_cache_hits_total",
			Help:        "ae:ctx/ae:tenant lookups that were a fresh hit.",
			ConstLabels: labels,
		}),
		negCacheLookups: f.NewCounter(prometheus.CounterOpts{
			Name:        "iam_authz_enrichment_negative_cache_lookups_total",
			Help:        "Total ae:neg lookups.",
			ConstLabels: labels,
		}),
		negCacheHits: f.NewCounter(prometheus.CounterOpts{
			Name:        "iam_authz_enrichment_negative_cache_hits_total",
			Help:        "ae:neg lookups that hit.",
			ConstLabels: labels,
		}),
		staleServedTotal: f.NewCounter(prometheus.CounterOpts{
			Name:        "iam_authz_enrichment_stale_served_total",
			Help:        "Requests served from a stale ae:ctx entry under §7's stale-if-error rule. A nonzero rate means a live dependency outage is in progress — page on this.",
			ConstLabels: labels,
		}),
		sfCoalescedTotal: f.NewCounter(prometheus.CounterOpts{
			Name:        "iam_authz_enrichment_singleflight_coalesced_total",
			Help:        "Membership-rebuild calls coalesced by singleflight instead of issued.",
			ConstLabels: labels,
		}),
		dependencyLatency: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:        "iam_authz_enrichment_dependency_request_seconds",
			Help:        "Outbound dependency call latency by dependency and operation (I-8 org-membership/get-memberships, I-12 tender-acl/get-tender-acl, I-14 org-membership/get-mfa-freshness).",
			Buckets:     prometheus.ExponentialBuckets(0.0005, 2, 16),
			ConstLabels: labels,
		}, []string{"dependency", "operation"}),
		tac4ErrorsTotal: f.NewCounter(prometheus.CounterOpts{
			Name:        "iam_authz_enrichment_tac4_errors_total",
			Help:        "Total GetTenderACL (TAC-4) errors — iam-tender-acl dependency failures that caused the tender-ACL overlay to fail closed. Distinct from legitimate DENY_TENDER_ACL_INSUFFICIENT policy denials.",
			ConstLabels: labels,
		}),
		evictionErrorsTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name:        "iam_authz_enrichment_eviction_errors_total",
			Help:        "Total best-effort EvictTenderACLForUser failures by event. A nonzero rate means ae:tender_acl entries for revoked/deleted users may persist until their 15s TTL.",
			ConstLabels: labels,
		}, []string{"event"}),
	}
}

func (r *Recorder) ObserveDecision(reason domain.DenyReason, allowed bool) {
	if allowed {
		r.decisionsTotal.WithLabelValues("allow").Inc()
		return
	}
	r.decisionsTotal.WithLabelValues("deny").Inc()
	r.denyReasonTotal.WithLabelValues(string(reason)).Inc()
}

func (r *Recorder) ObserveCacheHit(hit bool) {
	r.cacheLookups.Inc()
	if hit {
		r.cacheHits.Inc()
	}
}

func (r *Recorder) ObserveNegativeCacheHit(hit bool) {
	r.negCacheLookups.Inc()
	if hit {
		r.negCacheHits.Inc()
	}
}

func (r *Recorder) ObserveStaleIfErrorServed()    { r.staleServedTotal.Inc() }
func (r *Recorder) ObserveSingleflightCoalesced() { r.sfCoalescedTotal.Inc() }
func (r *Recorder) ObserveTACDependencyError()    { r.tac4ErrorsTotal.Inc() }

func (r *Recorder) ObserveEvictionError(event string) {
	r.evictionErrorsTotal.WithLabelValues(event).Inc()
}

func (r *Recorder) ObserveDependencyLatency(d time.Duration, dependency, operation string) {
	r.dependencyLatency.WithLabelValues(dependency, operation).Observe(d.Seconds())
}

func (r *Recorder) ObserveDecisionLatency(d time.Duration) { r.decisionLatency.Observe(d.Seconds()) }

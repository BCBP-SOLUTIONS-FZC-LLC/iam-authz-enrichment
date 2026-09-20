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
// authz_cache_hit_ratio and authz_negative_cache_hit_ratio (§10) are each
// exposed as a hits/lookups counter pair rather than a single ratio gauge —
// computing a ratio metric server-side and exposing it as a gauge is a
// well-known Prometheus anti-pattern (it can't be aggregated correctly
// across replicas or time windows); `rate(authz_cache_hits_total[5m]) /
// rate(authz_cache_lookups_total[5m])` in PromQL is the correct way to get
// the ratio the doc names.
type Recorder struct {
	decisionsTotal   *prometheus.CounterVec
	denyReasonTotal  *prometheus.CounterVec
	decisionLatency  prometheus.Histogram
	cacheLookups     prometheus.Counter
	cacheHits        prometheus.Counter
	negCacheLookups  prometheus.Counter
	negCacheHits     prometheus.Counter
	staleServedTotal prometheus.Counter
	sfCoalescedTotal prometheus.Counter
	i8Latency        prometheus.Histogram
	i12Latency       prometheus.Histogram
	i14Latency       prometheus.Histogram
}

// New builds and registers all authz_* metrics on reg — the same registry
// cmd/server's dedicated /metrics listener scrapes via gincommon.MetricsRegisterer().
// reg is optional (variadic so every existing zero-arg call site keeps
// compiling) and defaults to prometheus.DefaultRegisterer; cmd/server
// passes gincommon.MetricsRegisterer() AFTER ObservabilityMiddlewares has
// run, so these collectors land in the same registry and pick up the same
// {service, version} const labels as platform-gincommon's own HTTP/gRPC
// series (same convention as iam-org-membership / iam-user-profile).
func New(reg ...prometheus.Registerer) *Recorder {
	registerer := prometheus.DefaultRegisterer
	if len(reg) > 0 && reg[0] != nil {
		registerer = reg[0]
	}
	return newRecorder(registerer)
}

// gincommonLabels returns a copy of gincommon's {service, version} const
// labels so authz_* collectors scrape on the same registry and labels as
// HTTP/gRPC interceptor metrics. Returns nil when ObservabilityMiddlewares
// has not run yet, matching prometheus's "no const labels" zero value so
// unit tests that never bootstrap gincommon still register cleanly.
func gincommonLabels() prometheus.Labels {
	return constLabelsOrNil(gincommon.MetricsConstLabels())
}

func constLabelsOrNil(labels prometheus.Labels) prometheus.Labels {
	if len(labels) == 0 {
		return nil
	}
	return labels
}

// newRecorder builds and registers all authz_* metrics on reg. Factored out
// from New() so tests can pass an isolated prometheus.NewRegistry() instead
// of colliding on the process-wide default registry when multiple tests (or
// test files) each want their own Recorder.
func newRecorder(reg prometheus.Registerer) *Recorder {
	f := promauto.With(reg)
	labels := gincommonLabels()
	return &Recorder{
		decisionsTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name:        "authz_decisions_total",
			Help:        "Total ext_authz decisions, by decision (allow/deny).",
			ConstLabels: labels,
		}, []string{"decision"}),
		denyReasonTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name:        "authz_deny_reason_total",
			Help:        "Total deny decisions, by DenyReason.",
			ConstLabels: labels,
		}, []string{"reason"}),
		decisionLatency: f.NewHistogram(prometheus.HistogramOpts{
			Name:        "authz_decision_latency_seconds",
			Help:        "End-to-end Check() decision latency.",
			Buckets:     prometheus.ExponentialBuckets(0.0005, 2, 16), // 0.5ms .. ~16s
			ConstLabels: labels,
		}),
		cacheLookups: f.NewCounter(prometheus.CounterOpts{
			Name:        "authz_cache_lookups_total",
			Help:        "Total ae:ctx/ae:tenant lookups. Divide authz_cache_hits_total by this for the hit ratio.",
			ConstLabels: labels,
		}),
		cacheHits: f.NewCounter(prometheus.CounterOpts{
			Name:        "authz_cache_hits_total",
			Help:        "ae:ctx/ae:tenant lookups that were a fresh hit.",
			ConstLabels: labels,
		}),
		negCacheLookups: f.NewCounter(prometheus.CounterOpts{
			Name:        "authz_negative_cache_lookups_total",
			Help:        "Total ae:neg lookups.",
			ConstLabels: labels,
		}),
		negCacheHits: f.NewCounter(prometheus.CounterOpts{
			Name:        "authz_negative_cache_hits_total",
			Help:        "ae:neg lookups that hit.",
			ConstLabels: labels,
		}),
		staleServedTotal: f.NewCounter(prometheus.CounterOpts{
			Name:        "authz_stale_if_error_served_total",
			Help:        "Requests served from a stale ae:ctx entry under §7's stale-if-error rule. A nonzero rate means a live dependency outage is in progress — page on this.",
			ConstLabels: labels,
		}),
		sfCoalescedTotal: f.NewCounter(prometheus.CounterOpts{
			Name:        "authz_singleflight_coalesced_total",
			Help:        "Membership-rebuild calls coalesced by singleflight instead of issued.",
			ConstLabels: labels,
		}),
		i8Latency: f.NewHistogram(prometheus.HistogramOpts{
			Name:        "authz_i8_call_latency_seconds",
			Help:        "Org & Membership membership-rebuild (I-8) call latency.",
			Buckets:     prometheus.ExponentialBuckets(0.0005, 2, 16),
			ConstLabels: labels,
		}),
		i12Latency: f.NewHistogram(prometheus.HistogramOpts{
			Name:        "authz_i12_call_latency_seconds",
			Help:        "iam-tender-acl TAC-4 (formerly Org & Membership's I-12) tender-ACL call latency.",
			Buckets:     prometheus.ExponentialBuckets(0.0005, 2, 16),
			ConstLabels: labels,
		}),
		i14Latency: f.NewHistogram(prometheus.HistogramOpts{
			Name:        "authz_i14_call_latency_seconds",
			Help:        "Org & Membership MFA-freshness (I-14) call latency.",
			Buckets:     prometheus.ExponentialBuckets(0.0005, 2, 16),
			ConstLabels: labels,
		}),
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

func (r *Recorder) ObserveI8Latency(d time.Duration)  { r.i8Latency.Observe(d.Seconds()) }
func (r *Recorder) ObserveI12Latency(d time.Duration) { r.i12Latency.Observe(d.Seconds()) }
func (r *Recorder) ObserveI14Latency(d time.Duration) { r.i14Latency.Observe(d.Seconds()) }

func (r *Recorder) ObserveDecisionLatency(d time.Duration) { r.decisionLatency.Observe(d.Seconds()) }

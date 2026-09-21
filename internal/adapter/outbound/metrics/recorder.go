// Package metrics is the Prometheus-backed implementation of usecase.Recorder
// and consumer.ConsumerRecorder, aligned with the Enterprise Platform
// Observability Standard three-tier taxonomy.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// Config holds the observability-standard labeling context injected as
// ConstLabels on every metric so instrumentation code cannot omit or misspell
// them (Platform Observability Standard §8: "Service labels MUST be injected
// centrally").
type Config struct {
	Service     string // e.g. "iam-authz-enrichment"
	Environment string // e.g. "prod", "staging", "dev"
}

// dependency label values for iam_authz_enrichment_dependency_request_seconds.
const (
	DepI8  = "org-membership/i8"  // GetMemberships (I-8)
	DepI12 = "tender-acl/i12"     // GetTenderACL / TAC-4 (I-12)
	DepI14 = "org-membership/i14" // GetMFAFreshness (I-14)
)

// Recorder implements usecase.Recorder and consumer.ConsumerRecorder.
//
// Metric taxonomy (Platform Observability Standard):
//
//	Tier 3 – iam_authz_enrichment_* (service-specific):
//	  All authz decision, cache, singleflight, and dependency-call metrics.
//	  ConstLabels: service, environment.
//
//	Tier 1 – platform_* (canonical cross-domain):
//	  SQS consumer instrumentation: received / processed / failed per queue.
//	  ConstLabels: domain="iam", service, environment.
//
//	Backward compat – authz_* (DEPRECATED):
//	  Emitted in parallel during the migration window so existing dashboards
//	  and alert rules have time to cut over. Remove after migration is confirmed.
//
// Ratio metrics (cache hit rate, negative cache hit rate) are NOT exposed as
// gauge values — computing a ratio server-side is a well-known Prometheus
// anti-pattern (cannot aggregate correctly across replicas or time windows).
// Use rate(iam_authz_enrichment_cache_hits_total[5m]) /
// rate(iam_authz_enrichment_cache_lookups_total[5m]) in PromQL instead.
type Recorder struct {
	// ── Tier 3: iam_authz_enrichment_* ─────────────────────────────────────
	iaeDecisions    *prometheus.CounterVec
	iaeDenyReason   *prometheus.CounterVec
	iaeDecisionLat  prometheus.Histogram
	iaeCacheLookups prometheus.Counter
	iaeCacheHits    prometheus.Counter
	iaeNegLookups   prometheus.Counter
	iaeNegHits      prometheus.Counter
	iaeStaleServed  prometheus.Counter
	iaeSFCoalesced  prometheus.Counter
	iaeDepReq       *prometheus.HistogramVec // {dependency}

	// ── Tier 1: platform_* ──────────────────────────────────────────────────
	platMsgReceived  *prometheus.CounterVec // {queue}
	platMsgProcessed *prometheus.CounterVec // {queue}
	platMsgFailed    *prometheus.CounterVec // {queue}

	// ── Backward compat: authz_* (DEPRECATED — remove after migration) ──────
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

// New builds and registers all metrics. cfg provides the service and
// environment label values injected as ConstLabels on every metric. reg is
// optional (variadic) and defaults to prometheus.DefaultRegisterer; cmd/server
// passes gincommon.MetricsRegisterer() so all collectors land on the same
// registry as platform-gincommon's own metrics.
func New(cfg Config, reg ...prometheus.Registerer) *Recorder {
	registerer := prometheus.DefaultRegisterer
	if len(reg) > 0 && reg[0] != nil {
		registerer = reg[0]
	}
	return newRecorder(cfg, registerer)
}

// newRecorder is the testable constructor. Tests pass an isolated
// prometheus.NewRegistry() so parallel tests don't collide on the default registry.
func newRecorder(cfg Config, reg prometheus.Registerer) *Recorder {
	// Tier 3: iam_authz_enrichment_* with service + environment ConstLabels.
	iaeReg := prometheus.WrapRegistererWith(prometheus.Labels{
		"service":     cfg.Service,
		"environment": cfg.Environment,
	}, reg)
	iaeF := promauto.With(iaeReg)

	// Tier 1: platform_* with domain + service + environment ConstLabels.
	platReg := prometheus.WrapRegistererWith(prometheus.Labels{
		"domain":      "iam",
		"service":     cfg.Service,
		"environment": cfg.Environment,
	}, reg)
	platF := promauto.With(platReg)

	// Backward compat: plain registerer, no ConstLabels (legacy authz_* names).
	compatF := promauto.With(reg)

	return &Recorder{
		// ── Tier 3 ────────────────────────────────────────────────────────────
		iaeDecisions: iaeF.NewCounterVec(prometheus.CounterOpts{
			Name: "iam_authz_enrichment_decisions_total",
			Help: "Total ext_authz decisions by outcome.",
		}, []string{"decision"}),
		iaeDenyReason: iaeF.NewCounterVec(prometheus.CounterOpts{
			Name: "iam_authz_enrichment_deny_reason_total",
			Help: "Total deny decisions by DenyReason.",
		}, []string{"reason"}),
		iaeDecisionLat: iaeF.NewHistogram(prometheus.HistogramOpts{
			Name:    "iam_authz_enrichment_decision_latency_seconds",
			Help:    "End-to-end Check() decision latency.",
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16),
		}),
		iaeCacheLookups: iaeF.NewCounter(prometheus.CounterOpts{
			Name: "iam_authz_enrichment_cache_lookups_total",
			Help: "Total ae:ctx/ae:tenant lookups.",
		}),
		iaeCacheHits: iaeF.NewCounter(prometheus.CounterOpts{
			Name: "iam_authz_enrichment_cache_hits_total",
			Help: "ae:ctx/ae:tenant lookups that were a fresh hit.",
		}),
		iaeNegLookups: iaeF.NewCounter(prometheus.CounterOpts{
			Name: "iam_authz_enrichment_negative_cache_lookups_total",
			Help: "Total ae:neg lookups.",
		}),
		iaeNegHits: iaeF.NewCounter(prometheus.CounterOpts{
			Name: "iam_authz_enrichment_negative_cache_hits_total",
			Help: "ae:neg lookups that hit.",
		}),
		iaeStaleServed: iaeF.NewCounter(prometheus.CounterOpts{
			Name: "iam_authz_enrichment_stale_if_error_served_total",
			Help: "Requests served from a stale ae:ctx entry under §7 stale-if-error. A nonzero rate means a live dependency outage is in progress — page on this.",
		}),
		iaeSFCoalesced: iaeF.NewCounter(prometheus.CounterOpts{
			Name: "iam_authz_enrichment_singleflight_coalesced_total",
			Help: "Membership-rebuild calls coalesced by singleflight instead of issued.",
		}),
		iaeDepReq: iaeF.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "iam_authz_enrichment_dependency_request_seconds",
			Help:    "Outbound dependency call latency. dependency: org-membership/i8 (GetMemberships), tender-acl/i12 (GetTenderACL), org-membership/i14 (GetMFAFreshness).",
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16),
		}, []string{"dependency"}),

		// ── Tier 1 ────────────────────────────────────────────────────────────
		platMsgReceived: platF.NewCounterVec(prometheus.CounterOpts{
			Name: "platform_messages_received_total",
			Help: "Total SQS messages received for processing.",
		}, []string{"queue"}),
		platMsgProcessed: platF.NewCounterVec(prometheus.CounterOpts{
			Name: "platform_messages_processed_total",
			Help: "Total SQS messages successfully processed (including idempotency-skipped duplicates).",
		}, []string{"queue"}),
		platMsgFailed: platF.NewCounterVec(prometheus.CounterOpts{
			Name: "platform_messages_failed_total",
			Help: "Total SQS messages that failed processing and will be redelivered or moved to DLQ.",
		}, []string{"queue"}),

		// ── Backward compat: authz_* (DEPRECATED) ─────────────────────────────
		decisionsTotal: compatF.NewCounterVec(prometheus.CounterOpts{
			Name: "authz_decisions_total",
			Help: "DEPRECATED: use iam_authz_enrichment_decisions_total. Total ext_authz decisions, by decision (allow/deny).",
		}, []string{"decision"}),
		denyReasonTotal: compatF.NewCounterVec(prometheus.CounterOpts{
			Name: "authz_deny_reason_total",
			Help: "DEPRECATED: use iam_authz_enrichment_deny_reason_total. Total deny decisions, by DenyReason.",
		}, []string{"reason"}),
		decisionLatency: compatF.NewHistogram(prometheus.HistogramOpts{
			Name:    "authz_decision_latency_seconds",
			Help:    "DEPRECATED: use iam_authz_enrichment_decision_latency_seconds. End-to-end Check() decision latency.",
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16),
		}),
		cacheLookups: compatF.NewCounter(prometheus.CounterOpts{
			Name: "authz_cache_lookups_total",
			Help: "DEPRECATED: use iam_authz_enrichment_cache_lookups_total. Total ae:ctx/ae:tenant lookups.",
		}),
		cacheHits: compatF.NewCounter(prometheus.CounterOpts{
			Name: "authz_cache_hits_total",
			Help: "DEPRECATED: use iam_authz_enrichment_cache_hits_total. ae:ctx/ae:tenant lookups that were a fresh hit.",
		}),
		negCacheLookups: compatF.NewCounter(prometheus.CounterOpts{
			Name: "authz_negative_cache_lookups_total",
			Help: "DEPRECATED: use iam_authz_enrichment_negative_cache_lookups_total. Total ae:neg lookups.",
		}),
		negCacheHits: compatF.NewCounter(prometheus.CounterOpts{
			Name: "authz_negative_cache_hits_total",
			Help: "DEPRECATED: use iam_authz_enrichment_negative_cache_hits_total. ae:neg lookups that hit.",
		}),
		staleServedTotal: compatF.NewCounter(prometheus.CounterOpts{
			Name: "authz_stale_if_error_served_total",
			Help: "DEPRECATED: use iam_authz_enrichment_stale_if_error_served_total. Requests served from a stale ae:ctx entry under §7 stale-if-error.",
		}),
		sfCoalescedTotal: compatF.NewCounter(prometheus.CounterOpts{
			Name: "authz_singleflight_coalesced_total",
			Help: "DEPRECATED: use iam_authz_enrichment_singleflight_coalesced_total. Membership-rebuild calls coalesced by singleflight.",
		}),
		i8Latency: compatF.NewHistogram(prometheus.HistogramOpts{
			Name:    "authz_i8_call_latency_seconds",
			Help:    `DEPRECATED: use iam_authz_enrichment_dependency_request_seconds{dependency="org-membership/i8"}. Org & Membership membership-rebuild (I-8) call latency.`,
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16),
		}),
		i12Latency: compatF.NewHistogram(prometheus.HistogramOpts{
			Name:    "authz_i12_call_latency_seconds",
			Help:    `DEPRECATED: use iam_authz_enrichment_dependency_request_seconds{dependency="tender-acl/i12"}. iam-tender-acl TAC-4 (I-12) tender-ACL call latency.`,
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16),
		}),
		i14Latency: compatF.NewHistogram(prometheus.HistogramOpts{
			Name:    "authz_i14_call_latency_seconds",
			Help:    `DEPRECATED: use iam_authz_enrichment_dependency_request_seconds{dependency="org-membership/i14"}. Org & Membership MFA-freshness (I-14) call latency.`,
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16),
		}),
	}
}

// ── usecase.Recorder implementation ──────────────────────────────────────────

func (r *Recorder) ObserveDecision(reason domain.DenyReason, allowed bool) {
	decision := "deny"
	if allowed {
		decision = "allow"
	}
	r.iaeDecisions.WithLabelValues(decision).Inc()
	r.decisionsTotal.WithLabelValues(decision).Inc()
	if !allowed {
		r.iaeDenyReason.WithLabelValues(string(reason)).Inc()
		r.denyReasonTotal.WithLabelValues(string(reason)).Inc()
	}
}

func (r *Recorder) ObserveCacheHit(hit bool) {
	r.iaeCacheLookups.Inc()
	r.cacheLookups.Inc()
	if hit {
		r.iaeCacheHits.Inc()
		r.cacheHits.Inc()
	}
}

func (r *Recorder) ObserveNegativeCacheHit(hit bool) {
	r.iaeNegLookups.Inc()
	r.negCacheLookups.Inc()
	if hit {
		r.iaeNegHits.Inc()
		r.negCacheHits.Inc()
	}
}

func (r *Recorder) ObserveStaleIfErrorServed() {
	r.iaeStaleServed.Inc()
	r.staleServedTotal.Inc()
}

func (r *Recorder) ObserveSingleflightCoalesced() {
	r.iaeSFCoalesced.Inc()
	r.sfCoalescedTotal.Inc()
}

func (r *Recorder) ObserveI8Latency(d time.Duration) {
	r.iaeDepReq.WithLabelValues(DepI8).Observe(d.Seconds())
	r.i8Latency.Observe(d.Seconds())
}

func (r *Recorder) ObserveI12Latency(d time.Duration) {
	r.iaeDepReq.WithLabelValues(DepI12).Observe(d.Seconds())
	r.i12Latency.Observe(d.Seconds())
}

func (r *Recorder) ObserveI14Latency(d time.Duration) {
	r.iaeDepReq.WithLabelValues(DepI14).Observe(d.Seconds())
	r.i14Latency.Observe(d.Seconds())
}

func (r *Recorder) ObserveDecisionLatency(d time.Duration) {
	r.iaeDecisionLat.Observe(d.Seconds())
	r.decisionLatency.Observe(d.Seconds())
}

// ── consumer.ConsumerRecorder implementation ──────────────────────────────────

func (r *Recorder) ObserveMessageReceived(queue string) {
	r.platMsgReceived.WithLabelValues(queue).Inc()
}
func (r *Recorder) ObserveMessageProcessed(queue string) {
	r.platMsgProcessed.WithLabelValues(queue).Inc()
}
func (r *Recorder) ObserveMessageFailed(queue string) { r.platMsgFailed.WithLabelValues(queue).Inc() }

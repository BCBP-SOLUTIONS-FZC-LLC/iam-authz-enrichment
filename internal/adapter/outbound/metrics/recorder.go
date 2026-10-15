// Package metrics is the Prometheus-backed implementation of
// usecase.Recorder (§10). Cross-cutting instrumentation, not a business
// adapter — imported by both the usecase layer (via the interface) and
// cmd/server (composition root).
package metrics

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/gincommon"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// Recorder implements usecase.Recorder against gincommon's Prometheus
// registerer (the same registry cmd/server's /metrics listener scrapes via
// gincommon.MetricsHandler()).
//
// authz_cache_hit_ratio and authz_negative_cache_hit_ratio (§10) are each
// exposed as a hits/lookups counter pair rather than a single ratio gauge —
// computing a ratio metric server-side and exposing it as a gauge is a
// well-known Prometheus anti-pattern (it can't be aggregated correctly
// across replicas or time windows); `rate(iam_authz_enrichment_cache_hits_total[5m]) /
// rate(iam_authz_enrichment_cache_lookups_total[5m])` in PromQL is the correct way to get
// the ratio the doc names.
//
// The histograms are label-less HistogramVecs because gincommon's Tier 3
// constructor API has only NewHistogramVec; Observe goes through
// WithLabelValues() with no values.
type Recorder struct {
	decisionsTotal        *gincommon.CounterVec
	denyReasonTotal       *gincommon.CounterVec
	decisionLatency       *gincommon.HistogramVec
	cacheLookups          gincommon.Counter
	cacheHits             gincommon.Counter
	negCacheLookups       gincommon.Counter
	negCacheHits          gincommon.Counter
	staleServedTotal      gincommon.Counter
	sfCoalescedTotal      gincommon.Counter
	i8Latency             *gincommon.HistogramVec
	i12Latency            *gincommon.HistogramVec
	i14Latency            *gincommon.HistogramVec
	residencyUnknownTotal gincommon.Counter
}

// latencyBuckets is 0.5ms .. ~16s (16 exponential buckets, factor 2) —
// prometheus.ExponentialBuckets(0.0005, 2, 16), spelled out so this package
// never imports the Prometheus client (gincommon's metrics API is the only
// entry point, same as iam-org-membership).
var latencyBuckets = func() []float64 {
	b := make([]float64, 16)
	v := 0.0005
	for i := range b {
		b[i] = v
		v *= 2
	}
	return b
}()

// New builds and registers all iam_authz_enrichment_* metrics on reg through
// gincommon's Tier 3 constructors (NewCounterVec / NewCounter /
// NewHistogramVec), which validate every name and label against the
// Platform Observability Registry (iam_authz_enrichment_ prefix, _total /
// _seconds suffixes, no prohibited or centrally injected labels) and attach
// gincommon.MetricsConstLabels() — the same {domain, service, environment}
// as platform-gincommon's own HTTP/gRPC series. reg nil means
// gincommon.MetricsRegisterer(); tests pass an isolated registry.
//
// gincommon's metrics identity must already be initialised
// (ObservabilityMiddlewares or the grpccommon interceptors) — cmd/server
// calls this after ObservabilityMiddlewares. A validation or registration
// failure is returned rather than panicking, so cmd/server reports it like
// any other startup error.
func New(reg gincommon.Registerer) (*Recorder, error) {
	b := builder{reg: reg}
	r := &Recorder{
		decisionsTotal: b.counterVec("iam_authz_enrichment_decisions_total",
			"Total ext_authz decisions, by decision (allow/deny). Exactly one per Check call, including requests with no verified subject.", "decision"),
		denyReasonTotal: b.counterVec("iam_authz_enrichment_deny_reason_total",
			"Total deny decisions, by DenyReason, lowercased for the registry's snake_case reason vocabulary (DENY_SERVICE_UNAVAILABLE is deny_service_unavailable).", "reason"),
		decisionLatency: b.histogram("iam_authz_enrichment_decision_latency_seconds",
			"End-to-end Check() decision latency. Design budget: 15ms p99 (LLD §11.1)."),
		cacheLookups: b.counter("iam_authz_enrichment_cache_lookups_total",
			"Total ae:ctx/ae:tenant lookups. Divide iam_authz_enrichment_cache_hits_total by this for the hit ratio."),
		cacheHits: b.counter("iam_authz_enrichment_cache_hits_total",
			"ae:ctx/ae:tenant lookups that were a fresh hit."),
		negCacheLookups: b.counter("iam_authz_enrichment_negative_cache_lookups_total",
			"Total ae:neg lookups."),
		negCacheHits: b.counter("iam_authz_enrichment_negative_cache_hits_total",
			"ae:neg lookups that hit."),
		staleServedTotal: b.counter("iam_authz_enrichment_stale_if_error_served_total",
			"Requests served from a stale ae:ctx entry under §7's stale-if-error rule. A nonzero rate means a live dependency outage is in progress — page on this."),
		sfCoalescedTotal: b.counter("iam_authz_enrichment_singleflight_coalesced_total",
			"Membership-rebuild calls coalesced by singleflight instead of issued."),
		i8Latency: b.histogram("iam_authz_enrichment_i8_call_latency_seconds",
			"Org & Membership membership-rebuild (I-8) call latency."),
		i12Latency: b.histogram("iam_authz_enrichment_i12_call_latency_seconds",
			"iam-tender-acl TAC-4 (formerly Org & Membership's I-12) tender-ACL call latency; name kept for continuity (LLD §16 AE-19)."),
		i14Latency: b.histogram("iam_authz_enrichment_i14_call_latency_seconds",
			"Org & Membership MFA-freshness (I-14) call latency."),
		residencyUnknownTotal: b.counter("iam_authz_enrichment_authz_residency_unknown_total",
			"Allow decisions where Core returned an unrecognised residency_mode; the fail-safe 'strict' default was applied (LLD §16 AE-38, CD-37). A persistent nonzero rate means Core has not yet deployed the CD-37 field or is sending an unexpected value."),
	}
	if err := errors.Join(b.errs...); err != nil {
		return nil, fmt.Errorf("register iam_authz_enrichment metrics: %w", err)
	}
	return r, nil
}

// builder collects every constructor error so New reports all invalid
// metrics at once instead of only the first.
type builder struct {
	reg  gincommon.Registerer
	errs []error
}

func (b *builder) counterVec(name, help string, labels ...string) *gincommon.CounterVec {
	c, err := gincommon.NewCounterVec(b.reg, name, help, labels...)
	b.add(name, err)
	return c
}

func (b *builder) counter(name, help string) gincommon.Counter {
	c, err := gincommon.NewCounter(b.reg, name, help)
	b.add(name, err)
	return c
}

func (b *builder) histogram(name, help string) *gincommon.HistogramVec {
	h, err := gincommon.NewHistogramVec(b.reg, name, help, latencyBuckets)
	b.add(name, err)
	return h
}

// add records err, prefixed with the metric name — a bare Prometheus
// registration error ("duplicate metrics collector registration attempted")
// doesn't say which collector failed.
func (b *builder) add(name string, err error) {
	if err != nil {
		b.errs = append(b.errs, fmt.Errorf("%s: %w", name, err))
	}
}

func (r *Recorder) ObserveDecision(reason domain.DenyReason, allowed bool) {
	if allowed {
		r.decisionsTotal.WithLabelValues("allow").Inc()
		return
	}
	r.decisionsTotal.WithLabelValues("deny").Inc()
	// The registry's `reason` vocabulary is snake_case
	// (^[a-z][a-z0-9_]{0,63}$), so DENY_SERVICE_UNAVAILABLE is emitted as
	// deny_service_unavailable — alert rules match the lowercased value.
	r.denyReasonTotal.WithLabelValues(strings.ToLower(string(reason))).Inc()
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

func (r *Recorder) ObserveI8Latency(d time.Duration) {
	r.i8Latency.WithLabelValues().Observe(d.Seconds())
}
func (r *Recorder) ObserveI12Latency(d time.Duration) {
	r.i12Latency.WithLabelValues().Observe(d.Seconds())
}
func (r *Recorder) ObserveI14Latency(d time.Duration) {
	r.i14Latency.WithLabelValues().Observe(d.Seconds())
}

func (r *Recorder) ObserveDecisionLatency(d time.Duration) {
	r.decisionLatency.WithLabelValues().Observe(d.Seconds())
}

func (r *Recorder) ObserveResidencyUnknown() { r.residencyUnknownTotal.Inc() }

package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

func histogramSampleCount(t *testing.T, h prometheus.Histogram) uint64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, h.Write(&m))
	return m.GetHistogram().GetSampleCount()
}

func histogramVecSampleCount(t *testing.T, hv *prometheus.HistogramVec, lv ...string) uint64 {
	t.Helper()
	obs := hv.WithLabelValues(lv...)
	h, ok := obs.(prometheus.Histogram)
	require.True(t, ok, "HistogramVec observer must implement prometheus.Histogram")
	return histogramSampleCount(t, h)
}

// testConfig is a fixed Config used by all unit tests.
var testConfig = Config{Service: "iam-authz-enrichment", Environment: "test"}

// newTestRecorder builds a Recorder on its own private registry, so tests
// never collide with each other (or with a real New() call elsewhere in the
// process) over the process-wide default Prometheus registry.
func newTestRecorder(t *testing.T) *Recorder {
	t.Helper()
	return newRecorder(testConfig, prometheus.NewRegistry())
}

func TestNew_RegistersOnDefaultRegisterer(t *testing.T) {
	// The only test allowed to touch the real default registry — proves New()
	// wires newRecorder to prometheus.DefaultRegisterer as documented.
	// Deliberately not t.Parallel() to avoid racing any other test that
	// might also touch the default registry.
	r := New(testConfig)
	assert.NotNil(t, r)
}

func TestNew_RegistersOnExplicitRegisterer(t *testing.T) {
	t.Parallel()
	// Proves New(cfg, reg) wires newRecorder to the given registerer instead of
	// silently falling back to prometheus.DefaultRegisterer — the case
	// cmd/server exercises by passing gincommon.MetricsRegisterer().
	reg := prometheus.NewRegistry()
	r := New(testConfig, reg)
	assert.NotNil(t, r)

	mfs, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs, "iam_authz_enrichment_* and authz_* metrics should be registered on the explicit registerer")
}

// TestNew_TierLabelsPresent verifies that canonical Tier 3 metrics carry
// service + environment ConstLabels, and Tier 1 metrics also carry domain="iam".
// CounterVec and HistogramVec only appear in Gather output after at least one
// label series is created, so each checked metric is initialised with one call first.
func TestNew_TierLabelsPresent(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	r := New(testConfig, reg)

	// Initialise one series for each metric that needs checking, so it appears
	// in the gathered output. Plain Counter / Histogram always appear; CounterVec
	// / HistogramVec only appear after WithLabelValues is called.
	r.ObserveDecision("", true)                // iam_authz_enrichment_decisions_total
	r.ObserveDecisionLatency(time.Millisecond) // iam_authz_enrichment_decision_latency_seconds
	r.ObserveCacheHit(false)                   // iam_authz_enrichment_cache_lookups_total
	r.ObserveStaleIfErrorServed()              // iam_authz_enrichment_stale_if_error_served_total
	r.ObserveMessageReceived("q")              // platform_messages_received_total
	r.ObserveMessageProcessed("q")             // platform_messages_processed_total
	r.ObserveMessageFailed("q")                // platform_messages_failed_total

	mfs, err := reg.Gather()
	require.NoError(t, err)

	byName := make(map[string]*dto.MetricFamily, len(mfs))
	for _, mf := range mfs {
		byName[mf.GetName()] = mf
	}

	// Tier 3: must have service + environment ConstLabels.
	for _, name := range []string{
		"iam_authz_enrichment_decisions_total",
		"iam_authz_enrichment_decision_latency_seconds",
		"iam_authz_enrichment_cache_lookups_total",
		"iam_authz_enrichment_stale_if_error_served_total",
	} {
		mf, ok := byName[name]
		require.True(t, ok, "expected metric %s in gathered output", name)
		require.NotEmpty(t, mf.GetMetric(), "metric %s has no samples", name)
		labels := labelMap(mf.GetMetric()[0])
		assert.Equal(t, "iam-authz-enrichment", labels["service"], "metric %s missing service label", name)
		assert.Equal(t, "test", labels["environment"], "metric %s missing environment label", name)
	}

	// Tier 1: must have domain + service + environment ConstLabels.
	for _, name := range []string{
		"platform_messages_received_total",
		"platform_messages_processed_total",
		"platform_messages_failed_total",
	} {
		mf, ok := byName[name]
		require.True(t, ok, "expected metric %s in gathered output", name)
		require.NotEmpty(t, mf.GetMetric(), "metric %s has no samples", name)
		labels := labelMap(mf.GetMetric()[0])
		assert.Equal(t, "iam", labels["domain"], "metric %s missing domain label", name)
		assert.Equal(t, "iam-authz-enrichment", labels["service"], "metric %s missing service label", name)
		assert.Equal(t, "test", labels["environment"], "metric %s missing environment label", name)
	}
}

// labelMap returns the label name→value map for a single Metric proto.
func labelMap(m *dto.Metric) map[string]string {
	out := make(map[string]string, len(m.GetLabel()))
	for _, lp := range m.GetLabel() {
		out[lp.GetName()] = lp.GetValue()
	}
	return out
}

func TestObserveDecision_Allow(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveDecision("", true)

	// Legacy compat counters.
	assert.Equal(t, float64(1), testutil.ToFloat64(r.decisionsTotal.WithLabelValues("allow")))
	assert.Equal(t, float64(0), testutil.ToFloat64(r.decisionsTotal.WithLabelValues("deny")))
	// New canonical counters.
	assert.Equal(t, float64(1), testutil.ToFloat64(r.iaeDecisions.WithLabelValues("allow")))
	assert.Equal(t, float64(0), testutil.ToFloat64(r.iaeDecisions.WithLabelValues("deny")))
}

func TestObserveDecision_Deny(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveDecision(domain.DenyRoleInsufficient, false)

	// Legacy compat counters.
	assert.Equal(t, float64(1), testutil.ToFloat64(r.decisionsTotal.WithLabelValues("deny")))
	assert.Equal(t, float64(1), testutil.ToFloat64(r.denyReasonTotal.WithLabelValues(string(domain.DenyRoleInsufficient))))
	// New canonical counters.
	assert.Equal(t, float64(1), testutil.ToFloat64(r.iaeDecisions.WithLabelValues("deny")))
	assert.Equal(t, float64(1), testutil.ToFloat64(r.iaeDenyReason.WithLabelValues(string(domain.DenyRoleInsufficient))))
}

func TestObserveCacheHit(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveCacheHit(true)
	r.ObserveCacheHit(false)

	assert.Equal(t, float64(2), testutil.ToFloat64(r.cacheLookups))
	assert.Equal(t, float64(1), testutil.ToFloat64(r.cacheHits))
	assert.Equal(t, float64(2), testutil.ToFloat64(r.iaeCacheLookups))
	assert.Equal(t, float64(1), testutil.ToFloat64(r.iaeCacheHits))
}

func TestObserveNegativeCacheHit(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveNegativeCacheHit(true)
	r.ObserveNegativeCacheHit(false)

	assert.Equal(t, float64(2), testutil.ToFloat64(r.negCacheLookups))
	assert.Equal(t, float64(1), testutil.ToFloat64(r.negCacheHits))
	assert.Equal(t, float64(2), testutil.ToFloat64(r.iaeNegLookups))
	assert.Equal(t, float64(1), testutil.ToFloat64(r.iaeNegHits))
}

func TestObserveStaleIfErrorServed(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveStaleIfErrorServed()
	r.ObserveStaleIfErrorServed()

	assert.Equal(t, float64(2), testutil.ToFloat64(r.staleServedTotal))
	assert.Equal(t, float64(2), testutil.ToFloat64(r.iaeStaleServed))
}

func TestObserveSingleflightCoalesced(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveSingleflightCoalesced()

	assert.Equal(t, float64(1), testutil.ToFloat64(r.sfCoalescedTotal))
	assert.Equal(t, float64(1), testutil.ToFloat64(r.iaeSFCoalesced))
}

func TestObserveLatencies(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveI8Latency(5 * time.Millisecond)
	r.ObserveI12Latency(3 * time.Millisecond)
	r.ObserveI14Latency(2 * time.Millisecond)
	r.ObserveDecisionLatency(1 * time.Millisecond)

	// Legacy compat histograms still record.
	assert.Equal(t, uint64(1), histogramSampleCount(t, r.i8Latency))
	assert.Equal(t, uint64(1), histogramSampleCount(t, r.i12Latency))
	assert.Equal(t, uint64(1), histogramSampleCount(t, r.i14Latency))
	assert.Equal(t, uint64(1), histogramSampleCount(t, r.decisionLatency))
	// New canonical HistogramVec also records under the correct dependency label.
	assert.Equal(t, uint64(1), histogramVecSampleCount(t, r.iaeDepReq, DepI8))
	assert.Equal(t, uint64(1), histogramVecSampleCount(t, r.iaeDepReq, DepI12))
	assert.Equal(t, uint64(1), histogramVecSampleCount(t, r.iaeDepReq, DepI14))
	assert.Equal(t, uint64(1), histogramSampleCount(t, r.iaeDecisionLat))
}

func TestObserveMessageCounters(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveMessageReceived("membership-authz-q")
	r.ObserveMessageReceived("user-authz-q")
	r.ObserveMessageProcessed("membership-authz-q")
	r.ObserveMessageFailed("user-authz-q")

	assert.Equal(t, float64(1), testutil.ToFloat64(r.platMsgReceived.WithLabelValues("membership-authz-q")))
	assert.Equal(t, float64(1), testutil.ToFloat64(r.platMsgReceived.WithLabelValues("user-authz-q")))
	assert.Equal(t, float64(1), testutil.ToFloat64(r.platMsgProcessed.WithLabelValues("membership-authz-q")))
	assert.Equal(t, float64(1), testutil.ToFloat64(r.platMsgFailed.WithLabelValues("user-authz-q")))
}

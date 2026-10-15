package metrics

import (
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/gincommon"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/obsregistry"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// TestMain initialises gincommon's metrics identity once for this test
// binary: gincommon's Tier 3 constructors refuse to build a collector before
// it exists (cmd/server calls ObservabilityMiddlewares before metrics.New),
// and v1.4.0+ rejects a second, different identity in the same process.
func TestMain(m *testing.M) {
	_ = gincommon.ObservabilityMiddlewares(gincommon.Config{
		ServiceName:  "iam-authz-enrichment",
		BuildVersion: "test",
		Domain:       "iam",
		Environment:  "test",
	})
	os.Exit(m.Run())
}

func histogramSampleCount(t *testing.T, h *gincommon.HistogramVec) uint64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, h.WithLabelValues().(prometheus.Histogram).Write(&m))
	return m.GetHistogram().GetSampleCount()
}

// newTestRecorder builds a Recorder on its own private registry, so tests
// never collide with each other over gincommon's process-wide registerer.
func newTestRecorder(t *testing.T) *Recorder {
	t.Helper()
	r, err := New(prometheus.NewRegistry())
	require.NoError(t, err)
	return r
}

func TestNew_ReturnsRegistrationError(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	_, err := New(reg)
	require.NoError(t, err)

	r, err := New(reg)
	require.Error(t, err, "a second registration of the same collectors must fail, not panic")
	assert.Nil(t, r)
	assert.Contains(t, err.Error(), "iam_authz_enrichment_decisions_total")
	assert.Contains(t, err.Error(), "iam_authz_enrichment_i14_call_latency_seconds",
		"every failing collector is reported, not only the first")
}

func TestLatencyBuckets(t *testing.T) {
	t.Parallel()
	assert.Equal(t, prometheus.ExponentialBuckets(0.0005, 2, 16), latencyBuckets)
}

func TestNew_AppliesGincommonConstLabels(t *testing.T) {
	t.Parallel()
	want := gincommon.MetricsConstLabels()
	require.Equal(t, "iam-authz-enrichment", want["service"])
	require.Equal(t, "iam", want["domain"])
	require.Equal(t, "test", want["environment"])
	_, hasVersion := want["version"]
	require.False(t, hasVersion, "version is only on platform_build_info, never a const label")

	reg := prometheus.NewRegistry()
	r, err := New(reg)
	require.NoError(t, err)
	r.ObserveDecision("", true)
	r.ObserveDecision(domain.DenyRoleInsufficient, false)
	r.ObserveCacheHit(true)
	r.ObserveNegativeCacheHit(true)
	r.ObserveStaleIfErrorServed()
	r.ObserveSingleflightCoalesced()
	r.ObserveDecisionLatency(time.Millisecond)
	r.ObserveI8Latency(time.Millisecond)
	r.ObserveI12Latency(time.Millisecond)
	r.ObserveI14Latency(time.Millisecond)
	r.ObserveTACDependencyError()
	r.ObserveEvictionError("membership_revoked")

	mfs, err := reg.Gather()
	require.NoError(t, err)

	var found bool
	for _, mf := range mfs {
		if mf.GetName() != "iam_authz_enrichment_decisions_total" {
			continue
		}
		found = true
		require.NotEmpty(t, mf.GetMetric())
		labels := map[string]string{}
		for _, l := range mf.GetMetric()[0].GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		assert.Equal(t, want["service"], labels["service"])
		assert.Equal(t, want["domain"], labels["domain"])
		assert.Equal(t, want["environment"], labels["environment"])
		assert.NotContains(t, labels, "version")
	}
	assert.True(t, found, "iam_authz_enrichment_decisions_total must be gathered from the isolated registerer")

	// Enterprise Platform Observability Standard: every service metric is
	// named iam_authz_enrichment_* (Tier 3) and carries the identity labels.
	rep, err := obsregistry.Validate(reg, obsregistry.Options{})
	require.NoError(t, err)
	for _, f := range rep.Errors() {
		t.Errorf("observability standard violation: %v", f)
	}
	assert.Equal(t, "iam_authz_enrichment_", obsregistry.ServicePrefix("iam", "iam-authz-enrichment"))
}

func TestObserveDecision_Allow(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveDecision("", true)

	assert.Equal(t, float64(1), testutil.ToFloat64(r.decisionsTotal.WithLabelValues("allow")))
	assert.Equal(t, float64(0), testutil.ToFloat64(r.decisionsTotal.WithLabelValues("deny")))
}

func TestObserveDecision_Deny(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveDecision(domain.DenyRoleInsufficient, false)

	assert.Equal(t, float64(1), testutil.ToFloat64(r.decisionsTotal.WithLabelValues("deny")))
	assert.Equal(t, float64(1), testutil.ToFloat64(r.denyReasonTotal.WithLabelValues("deny_role_insufficient")))
}

func TestObserveCacheHit(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveCacheHit(true)
	r.ObserveCacheHit(false)

	assert.Equal(t, float64(2), testutil.ToFloat64(r.cacheLookups))
	assert.Equal(t, float64(1), testutil.ToFloat64(r.cacheHits))
}

func TestObserveNegativeCacheHit(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveNegativeCacheHit(true)
	r.ObserveNegativeCacheHit(false)

	assert.Equal(t, float64(2), testutil.ToFloat64(r.negCacheLookups))
	assert.Equal(t, float64(1), testutil.ToFloat64(r.negCacheHits))
}

func TestObserveStaleIfErrorServed(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveStaleIfErrorServed()
	r.ObserveStaleIfErrorServed()

	assert.Equal(t, float64(2), testutil.ToFloat64(r.staleServedTotal))
}

func TestObserveSingleflightCoalesced(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveSingleflightCoalesced()

	assert.Equal(t, float64(1), testutil.ToFloat64(r.sfCoalescedTotal))
}

func TestObserveLatencies(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveI8Latency(5 * time.Millisecond)
	r.ObserveI12Latency(3 * time.Millisecond)
	r.ObserveI14Latency(2 * time.Millisecond)
	r.ObserveDecisionLatency(1 * time.Millisecond)

	assert.Equal(t, uint64(1), histogramSampleCount(t, r.i8Latency))
	assert.Equal(t, uint64(1), histogramSampleCount(t, r.i12Latency))
	assert.Equal(t, uint64(1), histogramSampleCount(t, r.i14Latency))
	assert.Equal(t, uint64(1), histogramSampleCount(t, r.decisionLatency))
}

func TestObserveTACDependencyError(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveTACDependencyError()
	r.ObserveTACDependencyError()

	assert.Equal(t, float64(2), testutil.ToFloat64(r.tac4ErrorsTotal))
}

func TestObserveEvictionError_ByEvent(t *testing.T) {
	t.Parallel()
	r := newTestRecorder(t)

	r.ObserveEvictionError("membership_revoked")
	r.ObserveEvictionError("membership_revoked")
	r.ObserveEvictionError("user_deleted")

	assert.Equal(t, float64(2), testutil.ToFloat64(r.evictionErrors.WithLabelValues("membership_revoked")))
	assert.Equal(t, float64(1), testutil.ToFloat64(r.evictionErrors.WithLabelValues("user_deleted")))
}

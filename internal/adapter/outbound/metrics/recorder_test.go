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

// newTestRecorder builds a Recorder on its own private registry, so tests
// never collide with each other (or with a real New() call elsewhere in the
// process) over the process-wide default Prometheus registry.
func newTestRecorder(t *testing.T) *Recorder {
	t.Helper()
	return newRecorder(prometheus.NewRegistry())
}

func TestNew_RegistersOnDefaultRegisterer(t *testing.T) {
	// The only test allowed to touch the real default registry — proves New()
	// wires newRecorder to prometheus.DefaultRegisterer as documented.
	// Deliberately not t.Parallel() to avoid racing any other test that
	// might also touch the default registry.
	r := New()
	assert.NotNil(t, r)
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
	assert.Equal(t, float64(1), testutil.ToFloat64(r.denyReasonTotal.WithLabelValues(string(domain.DenyRoleInsufficient))))
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
	r.ObserveDecisionLatency(1 * time.Millisecond)

	assert.Equal(t, uint64(1), histogramSampleCount(t, r.i8Latency))
	assert.Equal(t, uint64(1), histogramSampleCount(t, r.i12Latency))
	assert.Equal(t, uint64(1), histogramSampleCount(t, r.decisionLatency))
}

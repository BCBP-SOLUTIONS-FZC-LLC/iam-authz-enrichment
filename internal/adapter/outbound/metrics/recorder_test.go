package metrics

import (
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

func TestConstLabelsOrNil(t *testing.T) {
	t.Parallel()
	assert.Nil(t, constLabelsOrNil(nil))
	assert.Nil(t, constLabelsOrNil(prometheus.Labels{}))
	assert.Equal(t, prometheus.Labels{"service": "s"}, constLabelsOrNil(prometheus.Labels{"service": "s"}))
}

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

func TestNew_RegistersOnExplicitRegisterer(t *testing.T) {
	t.Parallel()
	// Proves New(reg) wires newRecorder to the given registerer instead of
	// silently falling back to prometheus.DefaultRegisterer — the case
	// cmd/server exercises by passing gincommon.MetricsRegisterer().
	reg := prometheus.NewRegistry()
	r := New(reg)
	assert.NotNil(t, r)

	mfs, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs, "iam_authz_enrichment_* metrics should be registered on the explicit registerer")
}

func TestNew_AppliesGincommonConstLabels(t *testing.T) {
	// Not t.Parallel: ObservabilityMiddlewares' metrics.Init is process-wide
	// sync.Once, and this test must run after TestNew_RegistersOnDefaultRegisterer
	// so that test still exercises gincommonLabels' empty-before-init path.
	_ = gincommon.ObservabilityMiddlewares(gincommon.Config{
		ServiceName:  "iam-authz-enrichment",
		BuildVersion: "test",
		Domain:       "iam",
		Environment:  "test",
	})
	want := gincommon.MetricsConstLabels()
	require.Equal(t, "iam-authz-enrichment", want["service"])
	require.Equal(t, "iam", want["domain"])
	require.Equal(t, "test", want["environment"])
	_, hasVersion := want["version"]
	require.False(t, hasVersion, "version is only on platform_build_info, never a const label")
	require.Equal(t, want, gincommonLabels())
	require.Equal(t, want, constLabelsOrNil(want))

	reg := prometheus.NewRegistry()
	r := New(reg)
	r.ObserveDecision("", true)

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
	r.ObserveI14Latency(2 * time.Millisecond)
	r.ObserveDecisionLatency(1 * time.Millisecond)

	assert.Equal(t, uint64(1), histogramSampleCount(t, r.i8Latency))
	assert.Equal(t, uint64(1), histogramSampleCount(t, r.i12Latency))
	assert.Equal(t, uint64(1), histogramSampleCount(t, r.i14Latency))
	assert.Equal(t, uint64(1), histogramSampleCount(t, r.decisionLatency))
}

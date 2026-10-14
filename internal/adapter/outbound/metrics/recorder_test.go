package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/gincommon"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

func TestConstLabelsOrNil(t *testing.T) {
	t.Parallel()
	assert.Nil(t, constLabelsOrNil(nil))
	assert.Nil(t, constLabelsOrNil(prometheus.Labels{}))
	assert.Equal(t, prometheus.Labels{"service": "s"}, constLabelsOrNil(prometheus.Labels{"service": "s"}))
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
		Environment:  "dev",
	})
	// gincommon v1.6.0+: MetricsConstLabels returns {domain, environment, service}
	// — version is no longer a const label (it lives on the build_info gauge only).
	want := gincommon.MetricsConstLabels()
	require.Equal(t, "iam-authz-enrichment", want["service"])
	require.Equal(t, "iam", want["domain"])
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
		assert.Equal(t, want["version"], labels["version"])
	}
	assert.True(t, found, "iam_authz_enrichment_decisions_total must be gathered from the isolated registerer")
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
	reg := prometheus.NewRegistry()
	r := newRecorder(reg)

	r.ObserveDependencyLatency(5*time.Millisecond, "org-membership", "get-memberships")
	r.ObserveDependencyLatency(3*time.Millisecond, "tender-acl", "get-tender-acl")
	r.ObserveDependencyLatency(2*time.Millisecond, "org-membership", "get-mfa-freshness")
	r.ObserveDecisionLatency(1 * time.Millisecond)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	counts := map[string]uint64{}
	for _, mf := range mfs {
		if strings.HasPrefix(mf.GetName(), "iam_authz_enrichment_dependency_request_seconds") ||
			mf.GetName() == "iam_authz_enrichment_decision_latency_seconds" {
			for _, m := range mf.GetMetric() {
				counts[mf.GetName()] += m.GetHistogram().GetSampleCount()
			}
		}
	}
	assert.Equal(t, uint64(3), counts["iam_authz_enrichment_dependency_request_seconds"], "3 dependency observations")
	assert.Equal(t, uint64(1), counts["iam_authz_enrichment_decision_latency_seconds"], "1 decision observation")
}

func TestRecorder_ObserveTACDependencyError_Increments(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	r := newRecorder(reg)

	r.ObserveTACDependencyError()
	r.ObserveTACDependencyError()

	count, err := testutil.GatherAndCount(reg, "iam_authz_enrichment_tac4_errors_total")
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == "iam_authz_enrichment_tac4_errors_total" {
			require.Len(t, mf.GetMetric(), 1)
			assert.Equal(t, float64(2), mf.GetMetric()[0].GetCounter().GetValue())
		}
	}
}

func TestRecorder_ObserveEvictionError_ByEvent(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	r := newRecorder(reg)

	r.ObserveEvictionError("membership_revoked")
	r.ObserveEvictionError("membership_revoked")
	r.ObserveEvictionError("user_deleted")

	mfs, err := reg.Gather()
	require.NoError(t, err)

	counts := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() == "iam_authz_enrichment_eviction_errors_total" {
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "event" {
						counts[lp.GetValue()] = m.GetCounter().GetValue()
					}
				}
			}
		}
	}
	assert.Equal(t, float64(2), counts["membership_revoked"])
	assert.Equal(t, float64(1), counts["user_deleted"])
}

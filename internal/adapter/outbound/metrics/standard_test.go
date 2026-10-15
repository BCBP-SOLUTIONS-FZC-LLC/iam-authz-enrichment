package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/events"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/gincommon"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/grpccommon"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-pgcommon/v2/pkg/pgmetrics"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// TestStandard_ProductionRegistrationOrder reproduces cmd/server's metrics
// wiring on gincommon's real registerer — ObservabilityMiddlewares (TestMain)
// → metrics.New(nil) → events.InitMetrics → pgmetrics.InitWithIdentity → the
// grpccommon interceptors with the same identity — records a sample on every
// collector this service owns, and checks the result is one coherent
// registry. The only test that touches gincommon's real registerer: a second
// New(nil) in this binary would fail as a duplicate.
//
// With METRICS_SCRAPE_OUT set it writes the production /metrics handler's
// output there, for `metricslint check` and the inventory generator
// (.github/scripts/metricslint.sh).
func TestStandard_ProductionRegistrationOrder(t *testing.T) {
	r, err := New(nil)
	require.NoError(t, err)

	identity := gincommon.MetricsConstLabels()
	evWarnings, err := events.InitMetrics(events.MetricsIdentityFromLabels(identity), gincommon.MetricsRegisterer())
	require.NoError(t, err)
	assert.Empty(t, evWarnings, "no platform-events metric may be disabled")
	pgWarnings, err := pgmetrics.InitWithIdentity(pgmetrics.IdentityFromLabels(identity), gincommon.MetricsRegisterer())
	require.NoError(t, err)
	assert.Empty(t, pgWarnings, "no platform-pgcommon metric may be disabled")

	exerciseEveryCollector(r)
	exerciseGRPCInterceptors(t)

	gathered, err := gincommon.MetricsGatherer().Gather()
	require.NoError(t, err)
	names := map[string]bool{}
	for _, mf := range gathered {
		names[mf.GetName()] = true
		if !strings.HasPrefix(mf.GetName(), "platform_") && !strings.HasPrefix(mf.GetName(), "iam_") {
			continue // go_*, process_*, promhttp_* are exempt from the standard
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "version" {
					assert.Equal(t, "platform_build_info", mf.GetName(), "version is a const label only on platform_build_info")
				}
			}
		}
	}
	for _, want := range []string{
		"platform_build_info", "platform_library_info", "platform_grpc_server_handled_total",
		"iam_authz_enrichment_decisions_total", "iam_authz_enrichment_deny_reason_total",
		"iam_authz_enrichment_decision_latency_seconds", "iam_authz_enrichment_i14_call_latency_seconds",
		"iam_authz_enrichment_authz_residency_unknown_total",
	} {
		assert.True(t, names[want], "%s must be exported", want)
	}

	if out := os.Getenv("METRICS_SCRAPE_OUT"); out != "" {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
		req.Header.Set("Accept", "text/plain")
		gincommon.MetricsHandler().ServeHTTP(rec, req) // the production /metrics handler
		require.NoError(t, os.WriteFile(out, rec.Body.Bytes(), 0o600))
	}
}

// exerciseEveryCollector records one sample with every production label value
// on every collector this package owns, so the scrape exposes every label set
// (an unsampled vec has no series, and its values would go unchecked).
func exerciseEveryCollector(r *Recorder) {
	r.ObserveDecision("", true)
	for _, reason := range []domain.DenyReason{
		domain.DenyUnresolvableSubject, domain.DenyTenantReadOnly, domain.DenyMFAStale,
		domain.DenyTenderACLInsufficient, domain.DenyRoleInsufficient,
		domain.DenyServiceUnavailable, domain.DenyMalformedIdentity,
	} {
		r.ObserveDecision(reason, false)
	}
	r.ObserveCacheHit(true)
	r.ObserveNegativeCacheHit(true)
	r.ObserveStaleIfErrorServed()
	r.ObserveSingleflightCoalesced()
	r.ObserveDecisionLatency(time.Millisecond)
	r.ObserveI8Latency(time.Millisecond)
	r.ObserveI12Latency(time.Millisecond)
	r.ObserveI14Latency(time.Millisecond)
	r.ObserveResidencyUnknown()
}

// exerciseGRPCInterceptors runs one Check call through the production gRPC
// interceptor stack so platform_grpc_server_* have series in the scrape.
func exerciseGRPCInterceptors(t *testing.T) {
	t.Helper()
	chain := grpccommon.ObservabilityUnaryInterceptors(grpccommon.Config{
		ServiceName:  "iam-authz-enrichment",
		BuildVersion: "test",
		Domain:       "iam",
		Environment:  "test",
	})
	info := &grpc.UnaryServerInfo{FullMethod: "/envoy.service.auth.v3.Authorization/Check"}
	var handler grpc.UnaryHandler = func(context.Context, any) (any, error) { return struct{}{}, nil }
	for i := len(chain) - 1; i >= 0; i-- {
		next, ic := handler, chain[i]
		handler = func(ctx context.Context, req any) (any, error) { return ic(ctx, req, info, next) }
	}
	_, err := handler(t.Context(), struct{}{})
	require.NoError(t, err)
}

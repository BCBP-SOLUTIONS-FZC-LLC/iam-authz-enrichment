package orgmembership

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/gincommon"
)

func TestMain(m *testing.M) {
	// Same TracerProvider + W3C propagator gincommon installs in main() —
	// propagateTraceparent uses otel.GetTextMapPropagator() with no local
	// fallback, matching gincommon.PropagateHeaders.
	shutdown := gincommon.InitTracingFromEnv()
	code := m.Run()
	shutdown()
	os.Exit(code)
}

func TestPropagateTraceparent_NilRequestIsNoop(t *testing.T) {
	t.Parallel()
	assert.NotPanics(t, func() { propagateTraceparent(context.Background(), nil) })
}

func TestPropagateTraceparent_NoSpanInContextSkipsHeader(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	propagateTraceparent(context.Background(), req)
	assert.Empty(t, req.Header.Get("traceparent"),
		"invalid span context → traceparent header must not be set")
}

func TestPropagateTraceparent_SampledFlags01(t *testing.T) {
	t.Parallel()
	traceID, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	spanID, _ := trace.SpanIDFromHex("1112131415161718")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	propagateTraceparent(ctx, req)
	assert.Equal(t,
		"00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01",
		req.Header.Get("traceparent"),
		"sampled span must emit flags=01")
}

func TestPropagateTraceparent_UnsampledFlags00(t *testing.T) {
	t.Parallel()
	traceID, _ := trace.TraceIDFromHex("aabbccddeeff00112233445566778899")
	spanID, _ := trace.SpanIDFromHex("aa11bb22cc33dd44")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID,
		SpanID:  spanID,
		Remote:  true,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	propagateTraceparent(ctx, req)
	assert.Equal(t,
		"00-aabbccddeeff00112233445566778899-aa11bb22cc33dd44-00",
		req.Header.Get("traceparent"),
		"unsampled span must emit flags=00")
}

func TestInstrumentedHTTPClient_NonPositiveTimeoutDefaults(t *testing.T) {
	t.Parallel()
	c := instrumentedHTTPClient(0)
	require.NotNil(t, c.Transport)
	assert.Equal(t, 10*time.Millisecond, c.Timeout)
}

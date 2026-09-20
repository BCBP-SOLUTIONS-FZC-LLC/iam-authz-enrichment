package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/config"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/events"
	awssqs "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/test/fixtures"
)

// fakeSQSClient is a minimal SQSClientLike that never has a message to
// deliver — enough to exercise buildConsumer's real (non-idle) construction
// path and a full Start/Stop lifecycle without any network/AWS dependency.
type fakeSQSClient struct {
	receiveCalls atomic.Int64
}

func (f *fakeSQSClient) ReceiveMessage(ctx context.Context, _ *awssqs.ReceiveMessageInput, _ ...func(*awssqs.Options)) (*awssqs.ReceiveMessageOutput, error) {
	f.receiveCalls.Add(1)
	return &awssqs.ReceiveMessageOutput{}, nil
}

func (f *fakeSQSClient) DeleteMessage(context.Context, *awssqs.DeleteMessageInput, ...func(*awssqs.Options)) (*awssqs.DeleteMessageOutput, error) {
	return &awssqs.DeleteMessageOutput{}, nil
}

func (f *fakeSQSClient) ChangeMessageVisibility(context.Context, *awssqs.ChangeMessageVisibilityInput, ...func(*awssqs.Options)) (*awssqs.ChangeMessageVisibilityOutput, error) {
	return &awssqs.ChangeMessageVisibilityOutput{}, nil
}

func TestIdleConsumer_StartAndStopAreNoOps(t *testing.T) {
	t.Parallel()
	var c idleConsumer
	assert.NoError(t, c.Start(context.Background()))
	assert.NoError(t, c.Stop())
}

func TestBuildConsumer_EmptyQueueURL_ReturnsIdleConsumer(t *testing.T) {
	t.Parallel()
	c, err := buildConsumer("", testDeps(fixtures.NewFakeCache()), func(context.Context, events.Envelope[json.RawMessage]) error { return nil })
	require.NoError(t, err)
	assert.IsType(t, idleConsumer{}, c)
}

func TestBuildConsumer_RealQueueURL_RunsAndStops(t *testing.T) {
	t.Parallel()
	client := &fakeSQSClient{}
	// MaxReceiveCount is set here so the forced-to-0 path in buildConsumer
	// is exercised — SQS-native redrive must not be overridden in-process.
	deps := Deps{
		Client: client,
		SQS:    config.SQSConfigEnv{MaxReceiveCount: 5, Region: "ap-south-1"},
		Cache:  fixtures.NewFakeCache(),
		Log:    fixtures.NoopLogger{},
	}

	c, err := buildConsumer("http://queue/x", deps, func(context.Context, events.Envelope[json.RawMessage]) error { return nil })
	require.NoError(t, err)
	assert.NotNil(t, c)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	require.Eventually(t, func() bool { return client.receiveCalls.Load() > 0 }, 2*time.Second, 10*time.Millisecond)

	cancel()
	assert.NoError(t, c.Stop())
	<-done
}

// TestNewXConsumer_IdleAndReal exercises every exported consumer-builder's
// two paths (idle when unconfigured, real when given a queue URL) — the
// wrapper functions themselves, not just the handler closures they wrap.
func TestNewXConsumer_IdleAndReal(t *testing.T) {
	t.Parallel()
	builders := map[string]func(string, Deps, ...events.ConsumerOption) (events.Consumer, error){
		"membership": NewMembershipConsumer,
		"user":       NewUserConsumer,
		"billing":    NewBillingConsumer,
		"tenant":     NewTenantConsumer,
		"tender":     NewTenderConsumer,
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cache := fixtures.NewFakeCache()
			inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})
			deps := Deps{Client: &fakeSQSClient{}, Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv}

			idle, err := build("", deps)
			require.NoError(t, err)
			assert.IsType(t, idleConsumer{}, idle)

			real, err := build("http://queue/"+name, deps)
			require.NoError(t, err)
			assert.NotNil(t, real)
		})
	}
}

func TestProcessedHandler_EmptyEventID_ReturnsError(t *testing.T) {
	t.Parallel()
	wrapped := processedHandler(Deps{Cache: fixtures.NewFakeCache(), Log: fixtures.NoopLogger{}},
		func(context.Context, events.Envelope[json.RawMessage]) error { return nil })

	err := wrapped(context.Background(), events.Envelope[json.RawMessage]{ID: "", Type: "Any"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing id")
}

func TestDedupingHandler_MarkProcessedError_ProcessesAnyway(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.MarkProcessedErr = errors.New("valkey down")
	var called bool
	inner := func(context.Context, events.Envelope[json.RawMessage]) error {
		called = true
		return nil
	}
	wrapped := processedHandler(Deps{Cache: cache, Log: fixtures.NoopLogger{}}, inner)

	err := wrapped(context.Background(), events.Envelope[json.RawMessage]{ID: "evt-1"})

	require.NoError(t, err)
	assert.True(t, called, "when the idempotency check itself fails, the handler must still run rather than block eviction on a soft dependency")
}

func TestProcessedHandler_AlreadyClaimed_SkipsHandler(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	_, err := cache.MarkProcessed(context.Background(), ConsumerName, "evt-1")
	require.NoError(t, err)
	var called bool
	inner := func(context.Context, events.Envelope[json.RawMessage]) error {
		called = true
		return nil
	}
	wrapped := processedHandler(Deps{Cache: cache, Log: fixtures.NoopLogger{}}, inner)

	err = wrapped(context.Background(), events.Envelope[json.RawMessage]{ID: "evt-1"})

	require.NoError(t, err)
	assert.False(t, called, "MarkProcessed returning false must skip the handler")
}

func TestDedupingHandler_EvictProcessedFailsAfterHandlerError_StillPropagatesHandlerError(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictProcessedErr = errors.New("valkey down")
	inner := func(context.Context, events.Envelope[json.RawMessage]) error {
		return errors.New("handler failed")
	}
	wrapped := processedHandler(Deps{Cache: cache, Log: fixtures.NoopLogger{}}, inner)

	err := wrapped(context.Background(), events.Envelope[json.RawMessage]{ID: "evt-1"})

	require.Error(t, err)
	assert.Equal(t, "handler failed", err.Error(), "the original handler error must win even if the best-effort EvictProcessed cleanup also fails")
}

func TestProcessedHandler_HandlerPanics_EvictsMarkerAndRepanics(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	inner := func(context.Context, events.Envelope[json.RawMessage]) error {
		panic("boom")
	}
	wrapped := processedHandler(Deps{Cache: cache, Log: fixtures.NoopLogger{}}, inner)

	assert.PanicsWithValue(t, "boom", func() {
		_ = wrapped(context.Background(), events.Envelope[json.RawMessage]{ID: "evt-1"})
	})

	first, err := cache.MarkProcessed(context.Background(), ConsumerName, "evt-1")
	require.NoError(t, err)
	assert.True(t, first, "a handler panic must evict the idempotency marker so a redelivery is retried, not silently skipped forever")
}

func TestProcessedHandler_HandlerPanics_EvictProcessedAlsoFails_StillRepanics(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictProcessedErr = errors.New("valkey down")
	inner := func(context.Context, events.Envelope[json.RawMessage]) error {
		panic("boom")
	}
	wrapped := processedHandler(Deps{Cache: cache, Log: fixtures.NoopLogger{}}, inner)

	assert.PanicsWithValue(t, "boom", func() {
		_ = wrapped(context.Background(), events.Envelope[json.RawMessage]{ID: "evt-1"})
	}, "the original panic must still propagate even if the best-effort EvictProcessed cleanup also fails")
}

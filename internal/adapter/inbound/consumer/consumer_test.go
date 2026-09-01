package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	deps := Deps{Client: client, Region: "ap-south-1", Cache: fixtures.NewFakeCache(), Log: fixtures.NoopLogger{}}

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
			inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})
			deps := Deps{Client: &fakeSQSClient{}, Region: "ap-south-1", Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv}

			idle, err := build("", deps)
			require.NoError(t, err)
			assert.IsType(t, idleConsumer{}, idle)

			real, err := build("http://queue/"+name, deps)
			require.NoError(t, err)
			assert.NotNil(t, real)
		})
	}
}

// TC-062: a non-empty but syntactically invalid queue URL must fail at
// buildConsumer time (before any network call), giving a visible startup
// failure rather than silent per-message errors once the consumer is running.
func TestBuildConsumer_MalformedQueueURL_ReturnsError(t *testing.T) {
	t.Parallel()
	_, err := buildConsumer("not-a-url", testDeps(fixtures.NewFakeCache()), func(context.Context, events.Envelope[json.RawMessage]) error { return nil })
	require.Error(t, err, "a non-empty malformed queue URL must fail at construction, not silently at runtime")
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
	wrapped := dedupingHandler(Deps{Cache: cache, Log: fixtures.NoopLogger{}}, inner)

	err := wrapped(context.Background(), events.Envelope[json.RawMessage]{ID: "evt-1"})

	require.NoError(t, err)
	assert.True(t, called, "when the idempotency check itself fails, the handler must still run rather than block eviction on a soft dependency")
}

func TestDedupingHandler_EvictProcessedFailsAfterHandlerError_StillPropagatesHandlerError(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictProcessedErr = errors.New("valkey down")
	inner := func(context.Context, events.Envelope[json.RawMessage]) error {
		return errors.New("handler failed")
	}
	wrapped := dedupingHandler(Deps{Cache: cache, Log: fixtures.NoopLogger{}}, inner)

	err := wrapped(context.Background(), events.Envelope[json.RawMessage]{ID: "evt-1"})

	require.Error(t, err)
	assert.Equal(t, "handler failed", err.Error(), "the original handler error must win even if the best-effort EvictProcessed cleanup also fails")
}

// TC-057: two goroutines delivering the same event ID concurrently — exactly
// one handler must run. Redis SET NX atomicity guarantees this in production;
// FakeCache's mutex guarantees it in tests.
func TestDedupingHandler_ConcurrentSameEventID_ExactlyOneHandlerRuns(t *testing.T) {
	cache := fixtures.NewFakeCache()
	var handlerCount atomic.Int64
	release := make(chan struct{})
	inner := func(context.Context, events.Envelope[json.RawMessage]) error {
		<-release
		handlerCount.Add(1)
		return nil
	}
	wrapped := dedupingHandler(Deps{Cache: cache, Log: fixtures.NoopLogger{}}, inner)

	env := events.Envelope[json.RawMessage]{ID: "concurrent-event-id"}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = wrapped(context.Background(), env) }()
	go func() { defer wg.Done(); _ = wrapped(context.Background(), env) }()
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	assert.Equal(t, int64(1), handlerCount.Load(),
		"concurrent delivery of the same event ID must run the handler exactly once")
}

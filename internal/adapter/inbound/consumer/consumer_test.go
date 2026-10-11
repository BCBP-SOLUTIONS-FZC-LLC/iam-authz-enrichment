package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/config"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/events"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/events/mock"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awssqs "github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
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
	// MaxReceiveCount is set here so the override in buildConsumer is
	// exercised — the threshold is always dlqObserveReceiveCount.
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

// Without a DLQ publisher, DeadLetterHandler only observes: it logs and
// returns an error so platform-events never deletes the message, and SQS's
// redrive moves it.
func TestDeadLetterHandler_NoForwarding_LogsAndNeverAcks(t *testing.T) {
	log := &recordingLogger{}
	err := DeadLetterHandler("membership-authz-q", log, false)(context.Background(), events.Envelope[json.RawMessage]{ID: "e1", Type: "UserUpdated"})
	require.Error(t, err)
	assert.Len(t, log.errors, 1)
}

// With forwarding it returns nil — that is what lets platform-events forward
// the message to the DLQ and delete it from the source queue.
func TestDeadLetterHandler_Forwarding_LogsAndLetsTheLibraryForward(t *testing.T) {
	log := &recordingLogger{}
	err := DeadLetterHandler("membership-authz-q", log, true)(context.Background(), events.Envelope[json.RawMessage]{ID: "e1", Type: "UserUpdated"})
	require.NoError(t, err)
	assert.Len(t, log.errors, 1)
}

func TestNewDLQPublisher(t *testing.T) {
	p, err := NewDLQPublisher(awssqs.New(awssqs.Options{Region: "ap-south-1"}), "iam-authz-enrichment", fixtures.NoopLogger{})
	require.NoError(t, err)
	assert.NotNil(t, p)
}

// malformedSQSClient serves one message whose body is not an envelope, then
// nothing; it records deletes.
type malformedSQSClient struct {
	fakeSQSClient
	served  atomic.Bool
	deletes atomic.Int64
}

func (f *malformedSQSClient) ReceiveMessage(ctx context.Context, in *awssqs.ReceiveMessageInput, o ...func(*awssqs.Options)) (*awssqs.ReceiveMessageOutput, error) {
	if f.served.CompareAndSwap(false, true) {
		return &awssqs.ReceiveMessageOutput{Messages: []sqstypes.Message{{
			MessageId: awssdk.String("m1"), ReceiptHandle: awssdk.String("r1"), Body: awssdk.String("not an envelope"),
		}}}, nil
	}
	return f.fakeSQSClient.ReceiveMessage(ctx, in, o...)
}

func (f *malformedSQSClient) DeleteMessage(context.Context, *awssqs.DeleteMessageInput, ...func(*awssqs.Options)) (*awssqs.DeleteMessageOutput, error) {
	f.deletes.Add(1)
	return &awssqs.DeleteMessageOutput{}, nil
}

// With Deps.DLQ set, a malformed body is forwarded to the queue's DLQ before
// it is deleted — without forwarding, platform-events would delete it and
// the eviction it carried would leave no trace anywhere (LLD §16 AE-36).
func TestBuildConsumer_WithDLQ_ForwardsMalformedBody(t *testing.T) {
	t.Parallel()
	client := &malformedSQSClient{}
	dlq := &mock.DLQPublisher{}
	deps := Deps{
		Client: client,
		SQS:    config.SQSConfigEnv{Region: "ap-south-1"},
		Cache:  fixtures.NewFakeCache(),
		Log:    fixtures.NoopLogger{},
		DLQ:    dlq,
	}
	c, err := buildConsumer("http://queue/membership-authz-q", deps, func(context.Context, events.Envelope[json.RawMessage]) error { return nil })
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	require.Eventually(t, func() bool { return len(dlq.Sent()) == 1 }, 3*time.Second, 10*time.Millisecond)
	assert.Equal(t, "not an envelope", string(dlq.Sent()[0].Body))
	require.Eventually(t, func() bool { return client.deletes.Load() == 1 }, 3*time.Second, 10*time.Millisecond,
		"deleted from the source queue only after the forward")

	cancel()
	assert.NoError(t, c.Stop())
	<-done
}

func TestQueueName(t *testing.T) {
	assert.Equal(t, "user-authz-q", queueName("http://sqs.local/000000000000/user-authz-q"))
	assert.Equal(t, "user-authz-q", queueName("http://sqs.local/000000000000/user-authz-q/"))
	assert.Equal(t, "bare", queueName("bare"))
}

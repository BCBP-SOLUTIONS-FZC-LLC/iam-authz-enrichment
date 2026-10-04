package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	awssqs "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/inbound/consumer"
)

type noopLogger struct{}

func (noopLogger) Debug(string, map[string]interface{}) {}
func (noopLogger) Info(string, map[string]interface{})  {}
func (noopLogger) Warn(string, map[string]interface{})  {}
func (noopLogger) Error(string, map[string]interface{}) {}

// scriptedSQS is an SQS client whose ReceiveMessage returns receiveErr
// (nil = an empty, successful long poll). DeleteMessage and
// ChangeMessageVisibility are promoted from the nil embedded interface and
// must never be called by these tests.
type scriptedSQS struct {
	consumer.SQSClientLike
	receiveErr atomic.Pointer[error]
	calls      atomic.Int64
}

func (s *scriptedSQS) failWith(err error) { s.receiveErr.Store(&err) }

func (s *scriptedSQS) ReceiveMessage(context.Context, *awssqs.ReceiveMessageInput, ...func(*awssqs.Options)) (*awssqs.ReceiveMessageOutput, error) {
	s.calls.Add(1)
	if p := s.receiveErr.Load(); p != nil && *p != nil {
		return nil, *p
	}
	return &awssqs.ReceiveMessageOutput{}, nil
}

var errAccessDenied = errors.New("AccessDenied: not authorized to perform sqs:ReceiveMessage")

func receive(t *testing.T, c consumer.SQSClientLike) {
	t.Helper()
	_, _ = c.ReceiveMessage(context.Background(), &awssqs.ReceiveMessageInput{})
}

func TestReceiveTrackingClient_DelegatesAndRecordsOutcomes(t *testing.T) {
	inner := &scriptedSQS{}
	tr := &receiveTracker{}
	c := receiveTrackingClient{SQSClientLike: inner, tracker: tr}

	receive(t, c)
	inner.failWith(errAccessDenied)
	_, err := c.ReceiveMessage(context.Background(), &awssqs.ReceiveMessageInput{})
	require.ErrorIs(t, err, errAccessDenied, "the real client's error must be returned unchanged")
	receive(t, c)

	errs, ok := tr.snapshot()
	assert.Equal(t, uint64(2), errs)
	assert.Equal(t, uint64(1), ok)
	assert.Equal(t, int64(3), inner.calls.Load(), "every call must reach the real client")
}

func TestReceiveTrackingClient_ShutdownCancellationIsNotAnError(t *testing.T) {
	inner := &scriptedSQS{}
	inner.failWith(context.Canceled)
	tr := &receiveTracker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = receiveTrackingClient{SQSClientLike: inner, tracker: tr}.ReceiveMessage(ctx, &awssqs.ReceiveMessageInput{})

	errs, ok := tr.snapshot()
	assert.Zero(t, errs, "Stop() cancelling an in-flight long poll must not count towards the watchdog")
	assert.Zero(t, ok)
}

func TestReceiveTrackingClient_PerCallTimeoutIsAnError(t *testing.T) {
	inner := &scriptedSQS{}
	inner.failWith(context.DeadlineExceeded)
	tr := &receiveTracker{}

	receive(t, receiveTrackingClient{SQSClientLike: inner, tracker: tr})

	errs, _ := tr.snapshot()
	assert.Equal(t, uint64(1), errs, "a hung receive hitting its per-call deadline is a failed receive")
}

func TestReceiveWatchdog_Poll_SustainedFailure_ReachesStaleAfter(t *testing.T) {
	tr := &receiveTracker{}
	w := newReceiveWatchdog(map[string]*receiveTracker{"membership-authz-q": tr}, 3)

	for i := 0; i < 2; i++ {
		tr.record(context.Background(), errAccessDenied)
		assert.Equal(t, "", w.poll(), "must not fire before staleAfter consecutive failing polls")
	}
	tr.record(context.Background(), errAccessDenied)
	assert.Equal(t, "membership-authz-q", w.poll(), "the 3rd consecutive failing poll must cross staleAfter")
}

func TestReceiveWatchdog_Poll_FlakyQueueWithSuccesses_NeverFires(t *testing.T) {
	tr := &receiveTracker{}
	w := newReceiveWatchdog(map[string]*receiveTracker{"user-authz-q": tr}, 2)

	// Errors on every poll, but also a successful receive in between: the
	// consumer is working, so the watchdog must not restart the pod.
	for i := 0; i < 10; i++ {
		tr.record(context.Background(), errAccessDenied)
		tr.record(context.Background(), nil)
		assert.Equal(t, "", w.poll())
	}
}

func TestReceiveWatchdog_Poll_QueuesSharingAURL_TrackedIndependently(t *testing.T) {
	// Two friendly names configured with the same queue URL (e.g. a
	// copy-pasted env var) each have their own consumer and tracker, so one
	// cannot reset the other's streak.
	failing, healthy := &receiveTracker{}, &receiveTracker{}
	w := newReceiveWatchdog(map[string]*receiveTracker{
		"membership-authz-q": failing,
		"user-authz-q":       healthy,
	}, 3)

	for i := 0; i < 2; i++ {
		failing.record(context.Background(), errAccessDenied)
		healthy.record(context.Background(), nil)
		assert.Equal(t, "", w.poll())
	}
	failing.record(context.Background(), errAccessDenied)
	healthy.record(context.Background(), nil)
	assert.Equal(t, "membership-authz-q", w.poll(), "only the failing consumer is reported")
}

func TestReceiveWatchdog_Poll_RecoveryResetsStreak(t *testing.T) {
	tr := &receiveTracker{}
	w := newReceiveWatchdog(map[string]*receiveTracker{"membership-authz-q": tr}, 2)

	tr.record(context.Background(), errAccessDenied)
	assert.Equal(t, "", w.poll())
	// No new error this poll — streak resets.
	assert.Equal(t, "", w.poll())
	tr.record(context.Background(), errAccessDenied)
	assert.Equal(t, "", w.poll(), "streak must have reset, so one more failing poll alone must not fire")
}

func TestReceiveWatchdog_Poll_IdleQueue_NeverFires(t *testing.T) {
	tr := &receiveTracker{}
	w := newReceiveWatchdog(map[string]*receiveTracker{"tender-authz-q": tr}, 1)

	for i := 0; i < 5; i++ {
		tr.record(context.Background(), nil) // empty long polls are successes
		assert.Equal(t, "", w.poll())
	}
}

func TestRunReceiveErrorWatchdog_NoQueues_ReturnsImmediately(t *testing.T) {
	fatal := make(chan error, 1)

	done := make(chan struct{})
	go func() {
		runReceiveErrorWatchdog(context.Background(), nil, time.Millisecond, 1, fatal, noopLogger{})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runReceiveErrorWatchdog did not return with no queues configured")
	}
	assert.Empty(t, fatal)
}

// TestRunReceiveErrorWatchdog_SustainedFailure_PushesFatal drives the real
// wiring: a consumer loop calling ReceiveMessage through receiveTrackingClient
// against an SQS client that always fails.
func TestRunReceiveErrorWatchdog_SustainedFailure_PushesFatal(t *testing.T) {
	inner := &scriptedSQS{}
	inner.failWith(errAccessDenied)
	tr := &receiveTracker{}
	client := receiveTrackingClient{SQSClientLike: inner, tracker: tr}
	fatal := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for ctx.Err() == nil {
			_, _ = client.ReceiveMessage(ctx, &awssqs.ReceiveMessageInput{})
			time.Sleep(2 * time.Millisecond)
		}
	}()

	go runReceiveErrorWatchdog(ctx, map[string]*receiveTracker{"membership-authz-q": tr}, 5*time.Millisecond, 2, fatal, noopLogger{})

	select {
	case err := <-fatal:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "membership-authz-q")
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog never pushed to fatal despite sustained ReceiveMessage errors")
	}
}

func TestRunReceiveErrorWatchdog_ContextCancelled_ReturnsWithoutFiring(t *testing.T) {
	fatal := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		runReceiveErrorWatchdog(ctx, map[string]*receiveTracker{"q": {}}, time.Millisecond, 1000, fatal, noopLogger{})
		close(done)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runReceiveErrorWatchdog did not exit promptly on context cancellation")
	}
	assert.Empty(t, fatal)
}

// attrsSQS is a scriptedSQS that also answers GetQueueAttributes, like *sqs.Client.
type attrsSQS struct {
	scriptedSQS
	attrCalls atomic.Int64
}

//nolint:unparam // signature must match the SQS client's
func (s *attrsSQS) GetQueueAttributes(context.Context, *awssqs.GetQueueAttributesInput, ...func(*awssqs.Options)) (*awssqs.GetQueueAttributesOutput, error) {
	s.attrCalls.Add(1)
	return &awssqs.GetQueueAttributesOutput{Attributes: map[string]string{"ApproximateNumberOfMessages": "3"}}, nil
}

// The wrapper must expose GetQueueAttributes, or platform-events' queue-depth
// sampler (SQS_QUEUE_DEPTH_INTERVAL) type-asserts it away and never samples.
func TestReceiveTrackingClient_ExposesGetQueueAttributes(t *testing.T) {
	inner := &attrsSQS{}
	var c any = receiveTrackingClient{SQSClientLike: inner, tracker: &receiveTracker{}}

	api, ok := c.(queueAttributesAPI)
	require.True(t, ok, "the consumer client must satisfy platform-events' queue-depth interface")
	out, err := api.GetQueueAttributes(context.Background(), &awssqs.GetQueueAttributesInput{})
	require.NoError(t, err)
	assert.Equal(t, "3", out.Attributes["ApproximateNumberOfMessages"])
	assert.Equal(t, int64(1), inner.attrCalls.Load())
}

func TestReceiveTrackingClient_GetQueueAttributes_UnsupportedClient(t *testing.T) {
	c := receiveTrackingClient{SQSClientLike: &scriptedSQS{}, tracker: &receiveTracker{}}
	_, err := c.GetQueueAttributes(context.Background(), &awssqs.GetQueueAttributesInput{})
	require.Error(t, err)
}

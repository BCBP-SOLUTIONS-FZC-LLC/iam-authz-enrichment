package main

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noopLogger struct{}

func (noopLogger) Debug(string, map[string]interface{}) {}
func (noopLogger) Info(string, map[string]interface{})  {}
func (noopLogger) Warn(string, map[string]interface{})  {}
func (noopLogger) Error(string, map[string]interface{}) {}

func newTestReceiveErrorCounter(t *testing.T) (*prometheus.Registry, *prometheus.CounterVec) {
	t.Helper()
	reg := prometheus.NewRegistry()
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Name: sqsReceiveErrorsMetricName}, []string{"queue"})
	require.NoError(t, reg.Register(c))
	return reg, c
}

func TestSqsReceiveErrorCounts_ReadsQueueLabelledValues(t *testing.T) {
	reg, c := newTestReceiveErrorCounter(t)
	c.WithLabelValues("http://q/a").Add(3)
	c.WithLabelValues("http://q/b").Add(1)

	counts := sqsReceiveErrorCounts(reg)

	assert.Equal(t, 3.0, counts["http://q/a"])
	assert.Equal(t, 1.0, counts["http://q/b"])
}

func TestSqsReceiveErrorCounts_MetricNotRegistered_ReturnsEmpty(t *testing.T) {
	reg := prometheus.NewRegistry()

	assert.Empty(t, sqsReceiveErrorCounts(reg))
}

func TestReceiveWatchdog_Poll_SustainedFailure_ReachesStaleAfter(t *testing.T) {
	reg, c := newTestReceiveErrorCounter(t)
	w := newReceiveWatchdog(reg, map[string]string{"membership-authz-q": "http://q/membership"}, 3)

	for i := 0; i < 2; i++ {
		c.WithLabelValues("http://q/membership").Inc()
		assert.Equal(t, "", w.poll(), "must not fire before staleAfter consecutive increases")
	}
	c.WithLabelValues("http://q/membership").Inc()
	assert.Equal(t, "membership-authz-q", w.poll(), "the 3rd consecutive increase must cross staleAfter")
}

func TestReceiveWatchdog_Poll_AliasedQueueNames_StillReachesStaleAfter(t *testing.T) {
	reg, c := newTestReceiveErrorCounter(t)
	// Two friendly names sharing one queue URL (e.g. a copy-pasted env
	// var) must not corrupt each other's streak tracking.
	w := newReceiveWatchdog(reg, map[string]string{
		"membership-authz-q": "http://q/shared",
		"user-authz-q":       "http://q/shared",
	}, 3)

	for i := 0; i < 2; i++ {
		c.WithLabelValues("http://q/shared").Inc()
		assert.Equal(t, "", w.poll(), "must not fire before staleAfter consecutive increases")
	}
	c.WithLabelValues("http://q/shared").Inc()
	assert.NotEqual(t, "", w.poll(), "aliased names must not prevent the shared URL from ever reaching staleAfter")
}

func TestReceiveWatchdog_Poll_RecoveryResetsStreak(t *testing.T) {
	reg, c := newTestReceiveErrorCounter(t)
	w := newReceiveWatchdog(reg, map[string]string{"membership-authz-q": "http://q/membership"}, 2)

	c.WithLabelValues("http://q/membership").Inc()
	assert.Equal(t, "", w.poll())
	// No increase this poll (a successful receive happened in between) — streak resets.
	assert.Equal(t, "", w.poll())
	c.WithLabelValues("http://q/membership").Inc()
	assert.Equal(t, "", w.poll(), "streak must have reset, so one more increase alone must not fire")
}

func TestRunReceiveErrorWatchdog_NonGatherer_LogsAndReturns(t *testing.T) {
	fatal := make(chan error, 1)
	notAGatherer := struct{ prometheus.Registerer }{Registerer: prometheus.NewRegistry()}

	done := make(chan struct{})
	go func() {
		runReceiveErrorWatchdog(context.Background(), notAGatherer, map[string]string{"q": "http://q"}, time.Millisecond, 1, fatal, noopLogger{})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runReceiveErrorWatchdog did not return for a non-Gatherer registerer")
	}
	assert.Empty(t, fatal)
}

func TestRunReceiveErrorWatchdog_NoQueues_ReturnsImmediately(t *testing.T) {
	reg := prometheus.NewRegistry()
	fatal := make(chan error, 1)

	done := make(chan struct{})
	go func() {
		runReceiveErrorWatchdog(context.Background(), reg, nil, time.Millisecond, 1, fatal, noopLogger{})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runReceiveErrorWatchdog did not return with no queues configured")
	}
}

func TestRunReceiveErrorWatchdog_SustainedFailure_PushesFatal(t *testing.T) {
	reg, c := newTestReceiveErrorCounter(t)
	fatal := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			c.WithLabelValues("http://q/membership").Inc()
			time.Sleep(2 * time.Millisecond)
		}
	}()

	go runReceiveErrorWatchdog(ctx, reg, map[string]string{"membership-authz-q": "http://q/membership"}, 5*time.Millisecond, 2, fatal, noopLogger{})

	select {
	case err := <-fatal:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "membership-authz-q")
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog never pushed to fatal despite sustained ReceiveMessage errors")
	}
}

func TestRunReceiveErrorWatchdog_ContextCancelled_ReturnsWithoutFiring(t *testing.T) {
	reg := prometheus.NewRegistry()
	fatal := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		runReceiveErrorWatchdog(ctx, reg, map[string]string{"q": "http://q"}, time.Millisecond, 1000, fatal, noopLogger{})
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

package main

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	awssqs "github.com/aws/aws-sdk-go-v2/service/sqs"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/inbound/consumer"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
)

// platform-events' sqsConsumer.Start() never returns an error for a
// persistently failing ReceiveMessage loop (IAM permissions revoked, queue
// deleted, ...): it logs, backs off and retries forever. The watchdog below
// is the safety net that turns "stuck for minutes" into a fatal error so the
// orchestrator restarts the pod.
//
// It observes ReceiveMessage outcomes directly, by decorating the SQS client
// each consumer is built with (receiveTrackingClient), instead of reading a
// metric back from the Prometheus Gatherer. platform-events no longer emits a
// per-queue receive-error counter: its successor,
// platform_dependency_request_seconds_count{dependency="sqs",
// operation="receive_message",outcome="error"}, has no queue label and is
// fail-soft (disabled when a conflicting collector is registered), so it can
// neither say WHICH of the five consumers is stuck nor be relied on to exist.
// Owning the signal here keeps per-queue precision, sees successes as well
// as errors (a flaky-but-working queue never trips the watchdog), and does
// not depend on any metric name.

// receiveTracker counts one consumer's ReceiveMessage outcomes. Safe for
// concurrent use: the SQS consumer calls the client from its own goroutine
// while the watchdog reads from another.
type receiveTracker struct {
	errors    atomic.Uint64
	successes atomic.Uint64
}

func (t *receiveTracker) record(ctx context.Context, err error) {
	switch {
	case err == nil:
		t.successes.Add(1)
	case errors.Is(err, context.Canceled) && ctx.Err() != nil:
		// Stop()/shutdown cancelled an in-flight long poll — not a failure
		// (platform-events does not count it either).
	default:
		t.errors.Add(1)
	}
}

// snapshot returns the cumulative error and success counts.
func (t *receiveTracker) snapshot() (errs, successes uint64) {
	return t.errors.Load(), t.successes.Load()
}

// receiveTrackingClient is the SQS client handed to one consumer: every
// method delegates to the real client; ReceiveMessage outcomes are also
// recorded on tracker.
type receiveTrackingClient struct {
	consumer.SQSClientLike
	tracker *receiveTracker
}

func (c receiveTrackingClient) ReceiveMessage(ctx context.Context, params *awssqs.ReceiveMessageInput, optFns ...func(*awssqs.Options)) (*awssqs.ReceiveMessageOutput, error) {
	out, err := c.SQSClientLike.ReceiveMessage(ctx, params, optFns...)
	c.tracker.record(ctx, err)
	return out, err
}

// receiveWatchdog tracks, per queue, how many consecutive polls saw at least
// one new ReceiveMessage error and not a single successful receive. A queue
// that is merely flaky has a success between polls and its streak resets; a
// queue whose permissions were revoked or URL deleted fails every attempt
// (platform-events caps its receive backoff below the poll interval), so its
// streak grows on every poll.
type receiveWatchdog struct {
	queues     map[string]*receiveTracker // friendly queue name -> tracker
	staleAfter int
	lastErrs   map[string]uint64
	lastOK     map[string]uint64
	streak     map[string]int
}

func newReceiveWatchdog(queues map[string]*receiveTracker, staleAfter int) *receiveWatchdog {
	return &receiveWatchdog{
		queues:     queues,
		staleAfter: staleAfter,
		lastErrs:   make(map[string]uint64, len(queues)),
		lastOK:     make(map[string]uint64, len(queues)),
		streak:     make(map[string]int, len(queues)),
	}
}

// poll updates every queue's streak and returns the name of a queue whose
// streak reached staleAfter on this call, or "" if none did. Each consumer
// has its own tracker, so two names configured with the same queue URL are
// tracked independently and cannot reset each other's streak.
func (w *receiveWatchdog) poll() string {
	stuck := ""
	for name, t := range w.queues {
		errs, ok := t.snapshot()
		if errs > w.lastErrs[name] && ok == w.lastOK[name] {
			w.streak[name]++
		} else {
			w.streak[name] = 0
		}
		w.lastErrs[name], w.lastOK[name] = errs, ok
		if w.streak[name] == w.staleAfter && stuck == "" {
			stuck = name
		}
	}
	return stuck
}

// runReceiveErrorWatchdog polls the queues' trackers every pollInterval and
// pushes to fatal the first time a queue has failed on staleAfter consecutive
// polls with no successful receive — roughly staleAfter*pollInterval without
// one successful ReceiveMessage.
func runReceiveErrorWatchdog(ctx context.Context, queues map[string]*receiveTracker, pollInterval time.Duration, staleAfter int, fatal chan<- error, log usecase.Logger) {
	if len(queues) == 0 {
		return
	}
	w := newReceiveWatchdog(queues, staleAfter)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		stuck := w.poll()
		if stuck == "" {
			continue
		}
		err := fmt.Errorf("%s: %d consecutive polls (~%s) of SQS ReceiveMessage errors with no successful receive",
			stuck, staleAfter, pollInterval*time.Duration(staleAfter))
		log.Error("sqs receive-error watchdog: consumer appears stuck", map[string]interface{}{
			"queue": stuck, "error": err.Error(),
		})
		select {
		case fatal <- err:
		default:
		}
		return
	}
}

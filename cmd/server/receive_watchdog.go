package main

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
)

// sqsReceiveErrorsMetricName is platform-events' own SQS ReceiveMessage
// error counter — its package comment says "alert when these are
// non-zero". sqsConsumer.Start() never returns an error for a persistently
// failing receive loop (it retries forever internally), so this is the
// only externally observable signal that a consumer is stuck.
const sqsReceiveErrorsMetricName = "sqs_receive_errors_total"

// sqsReceiveErrorCounts extracts the current per-queue value of
// sqsReceiveErrorsMetricName from a Gatherer snapshot, keyed by the
// "queue" label value (the queue URL). Returns an empty map — never an
// error — if metrics aren't registered yet or Gather itself fails; the
// watchdog then simply sees no evidence of failure that poll.
func sqsReceiveErrorCounts(g prometheus.Gatherer) map[string]float64 {
	counts := make(map[string]float64)
	families, err := g.Gather()
	if err != nil {
		return counts
	}
	for _, mf := range families {
		if mf.GetName() != sqsReceiveErrorsMetricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			var queue string
			for _, l := range m.GetLabel() {
				if l.GetName() == "queue" {
					queue = l.GetValue()
				}
			}
			if queue != "" {
				counts[queue] = m.GetCounter().GetValue()
			}
		}
	}
	return counts
}

// receiveWatchdog tracks, per queue, how many consecutive polls observed
// its error counter increase. A genuine ReceiveMessage success resets
// platform-events' internal receiveBackoff — it never logs or increments
// the error counter — so a queue that is merely flaky will show a poll
// with no increase and its streak resets to 0 well before staleAfter. A
// queue whose permissions were revoked or whose URL was deleted fails
// every attempt, so its counter increases on every single poll.
type receiveWatchdog struct {
	gatherer   prometheus.Gatherer
	queues     map[string]string // friendly name -> queue URL
	staleAfter int
	last       map[string]float64 // keyed by queue URL
	streak     map[string]int     // keyed by queue URL
}

func newReceiveWatchdog(gatherer prometheus.Gatherer, queues map[string]string, staleAfter int) *receiveWatchdog {
	return &receiveWatchdog{
		gatherer:   gatherer,
		queues:     queues,
		staleAfter: staleAfter,
		last:       make(map[string]float64, len(queues)),
		streak:     make(map[string]int, len(queues)),
	}
}

// poll gathers current counts and returns the friendly name of a queue
// whose streak just reached staleAfter this call, or "" if none did.
//
// Updates each distinct URL's streak exactly once per poll, even when two
// friendly names alias the same URL (e.g. a copy-pasted queue URL) — doing
// the update inline in a single per-name loop would have each alias read
// the other's just-written w.last, permanently forcing the streak back to
// 0 every poll and making the corresponding queue impossible to detect as
// stuck, defeating the whole point of this watchdog for that URL.
func (w *receiveWatchdog) poll() string {
	counts := sqsReceiveErrorCounts(w.gatherer)

	urls := make(map[string]struct{}, len(w.queues))
	for _, url := range w.queues {
		urls[url] = struct{}{}
	}
	for url := range urls {
		cur := counts[url]
		if cur > w.last[url] {
			w.streak[url]++
		} else {
			w.streak[url] = 0
		}
		w.last[url] = cur
	}

	for name, url := range w.queues {
		if w.streak[url] == w.staleAfter {
			return name
		}
	}
	return ""
}

// runReceiveErrorWatchdog polls queues' sqs_receive_errors_total every
// pollInterval and pushes to fatal the first time a queue's counter has
// increased on staleAfter consecutive polls in a row — i.e. roughly
// staleAfter*pollInterval has passed with not one successful receive.
// Skips entirely (logging why) if reg isn't also a prometheus.Gatherer —
// true for gincommon.MetricsRegisterer() in every real deployment, but
// guarded so a future non-Gatherer registerer degrades to "no extra
// safety net" instead of a nil-interface panic.
func runReceiveErrorWatchdog(ctx context.Context, reg prometheus.Registerer, queues map[string]string, pollInterval time.Duration, staleAfter int, fatal chan<- error, log usecase.Logger) {
	gatherer, ok := reg.(prometheus.Gatherer)
	if !ok {
		log.Warn("sqs receive-error watchdog disabled: metrics registerer is not a prometheus.Gatherer", nil)
		return
	}
	if len(queues) == 0 {
		return
	}
	w := newReceiveWatchdog(gatherer, queues, staleAfter)
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

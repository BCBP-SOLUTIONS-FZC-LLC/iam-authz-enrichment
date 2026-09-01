// Package consumer wires the four (five, counting billing separately from
// membership as the doc's table does) inbound SQS queues from LLD §5 to the
// usecase.Invalidator. This service consumes only — it publishes nothing.
//
// DLQ handling (§5) is deliberately NOT implemented in application code: the
// "maxReceiveCount=5 before landing in its own -dlq" behavior is SQS's own
// native redrive policy, configured on the queue resource itself (see
// scripts/init-localstack.sh for the local/LocalStack equivalent of the
// Terraform-managed RedrivePolicy in real AWS). A handler returning a
// non-nil error simply leaves the message undeleted for redelivery — SQS
// does the counting and the eventual DLQ move on its own. Building a
// second, application-level DLQ mechanism on top of that would be exactly
// the "special-case DLQ-replay mechanism" §5 says not to build.
package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/events"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
)

// IdempotencyCache is the port this package needs for consumer dedup (§5):
// Valkey SET NX keyed by event ID, the functional equivalent of
// INSERT...ON CONFLICT DO NOTHING for a service with no database.
type IdempotencyCache interface {
	MarkProcessed(ctx context.Context, eventID string) (bool, error)
	// EvictProcessed un-marks an event ID. Called only when the handler for
	// a just-marked event fails, so a future redelivery gets a real retry
	// instead of being silently swallowed as "already processed" — without
	// this, a message that always fails would falsely dedup-ack on its
	// second delivery and never reach the DLQ after §5's maxReceiveCount.
	EvictProcessed(ctx context.Context, eventID string) error
}

// Logger mirrors usecase.Logger's shape (see that type's doc comment for why
// every IAM service declares its own copy of this interface).
type Logger interface {
	Debug(msg string, fields map[string]interface{})
	Info(msg string, fields map[string]interface{})
	Warn(msg string, fields map[string]interface{})
	Error(msg string, fields map[string]interface{})
}

// SQSClientLike is the subset of *sqs.Client this package needs — satisfied
// by the real AWS SDK client and by a fake in tests.
type SQSClientLike = events.SQSClientLike

// Deps bundles what every one of the five consumers is built from.
type Deps struct {
	Client      SQSClientLike
	Region      string
	EndpointURL string
	Cache       IdempotencyCache
	Log         Logger
	Invalidator *usecase.Invalidator
}

// idleConsumer is a no-op Consumer used when a queue URL is unconfigured —
// same MVP-idle pattern as iam-user-profile's consumer wiring, useful for
// partial local dev setups that don't run all five queues.
type idleConsumer struct{}

func (idleConsumer) Start(context.Context) error { return nil }
func (idleConsumer) Stop() error                 { return nil }

// dedupingHandler wraps handler with the §5 idempotency check: a message
// whose event ID has already been marked processed is acknowledged
// (deleted) without being handled again.
func dedupingHandler(deps Deps, handler events.Handler) events.Handler {
	return func(ctx context.Context, env events.Envelope[json.RawMessage]) error {
		first, err := deps.Cache.MarkProcessed(ctx, env.ID)
		if err != nil {
			// Valkey is unavailable for the dedup check — process anyway
			// rather than block eviction on a soft dependency. At worst this
			// re-applies an idempotent eviction, never a correctness issue.
			deps.Log.Warn("idempotency check failed, processing anyway", map[string]interface{}{
				"error": err.Error(), "event_id": env.ID, "event_type": env.Type,
			})
			return handler(ctx, env)
		}
		if !first {
			return nil
		}
		if handlerErr := handler(ctx, env); handlerErr != nil {
			if evictErr := deps.Cache.EvictProcessed(ctx, env.ID); evictErr != nil {
				deps.Log.Warn("failed to evict idempotency marker after handler error", map[string]interface{}{
					"error": evictErr.Error(), "event_id": env.ID, "event_type": env.Type,
				})
			}
			return handlerErr
		}
		return nil
	}
}

// buildConsumer constructs an SQS consumer for queueURL, or an idleConsumer
// if queueURL is empty. opts passes through to events.NewSQSConsumerWithClient
// — mainly used by tests to tune WithVisibilityTimeout for a fast DLQ cycle.
func buildConsumer(queueURL string, deps Deps, handler events.Handler, opts ...events.ConsumerOption) (events.Consumer, error) {
	if queueURL == "" {
		return idleConsumer{}, nil
	}
	u, err := url.ParseRequestURI(queueURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("sqs: queue URL %q must be an http or https URL", queueURL)
	}
	return events.NewSQSConsumerWithClient(events.SQSConfig{
		QueueURL:    queueURL,
		Region:      deps.Region,
		EndpointURL: deps.EndpointURL,
		MaxMessages: 10,
		WaitSeconds: 20,
		Logger:      deps.Log,
	}, deps.Client, dedupingHandler(deps, handler), opts...)
}

// Package consumer wires the five inbound SQS queues from LLD §5 to the
// usecase.Invalidator through platform-events (pkg/events + pkg/config +
// pkg/outbox). LoadPlatform assembles the same SQS / SNS / outbox Config
// iam-user-profile / iam-org-membership pass to NewSQSConsumer /
// NewSNSPublisher / NewRunner; this service consumes only (HLD §5.4 /
// EVT-2), so cmd/server skips NewSNSPublisher, outbox.ApplySchema, and
// NewRunner after LoadPlatform. Dedup is Envelope.ID via skipDuplicate /
// ackUnknown (same helpers as those siblings); the store is Valkey SET NX
// because there is no processed_events table (LLD AE-6).
//
// DLQ handling (§5) is deliberately NOT implemented in application code: the
// "maxReceiveCount=5 before landing in its own -dlq" behavior is SQS's own
// native redrive policy, configured on the queue resource itself (see
// scripts/init-localstack.sh for the local/LocalStack equivalent of the
// Terraform-managed RedrivePolicy in real AWS). A handler returning a
// non-nil error simply leaves the message undeleted for redelivery — SQS
// does the counting and the eventual DLQ move on its own. Building a
// second, application-level DLQ mechanism on top of that would be exactly
// the "special-case DLQ-replay mechanism" §5 says not to build. The one
// addition is observability-only: DeadLetterHandler logs a message's last
// delivery before SQS moves it, and never acks it (see dlqObserveReceiveCount).
package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/config"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/events"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
)

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
	SQS         config.SQSConfigEnv
	Cache       IdempotencyStore
	Log         Logger
	Invalidator *usecase.Invalidator
}

// idleConsumer is a no-op Consumer used when a queue URL is unconfigured —
// same MVP-idle pattern as iam-user-profile's consumer wiring, useful for
// partial local dev setups that don't run all five queues.
type idleConsumer struct{}

func (idleConsumer) Start(context.Context) error { return nil }
func (idleConsumer) Stop() error                 { return nil }

// buildConsumer constructs an SQS consumer for queueURL, or an idleConsumer
// if queueURL is empty. Construction goes through platform-events
// config.SQSConfigFromEnv / SQSConsumerOptions so MaxMessages, WaitSeconds,
// VisibilityTimeout, and Concurrency come from the same env-derived struct
// iam-org-membership / iam-user-profile use — not a hand-rolled SQSConfig.
//
// The env's MaxReceiveCount is ignored: this service's DLQ is SQS-native
// redrive on the queue resource, and SQS_MAX_RECEIVE_COUNT passed through
// SQSConsumerOptions WITHOUT a dead-letter handler would make platform-events
// delete the message in-process instead of leaving it for the queue's
// RedrivePolicy. Instead WithMaxReceiveCount(dlqObserveReceiveCount) is
// always paired with DeadLetterHandler, which observes and never acks.
//
// opts passes through to events.NewSQSConsumerWithClient — mainly used by
// tests to tune WithVisibilityTimeout for a fast DLQ cycle, and by
// cmd/server for per-queue WithConcurrency.
func buildConsumer(queueURL string, deps Deps, handler events.Handler, opts ...events.ConsumerOption) (events.Consumer, error) {
	if queueURL == "" {
		return idleConsumer{}, nil
	}
	env := deps.SQS
	env.QueueURL = queueURL
	env.MaxReceiveCount = 0 // replaced below by dlqObserveReceiveCount + DeadLetterHandler
	cfg := config.SQSConfigFromEnv(env, eventsLogger{deps.Log})
	// GlueDecoder strips the Glue wire header producers add once their
	// registry is configured. Decode only runs when Envelope.SchemaID is
	// non-empty, so plain-JSON envelopes pass through untouched.
	built := []events.ConsumerOption{events.WithConsumerCodec(GlueDecoder{})}
	built = append(built, config.SQSConsumerOptions(env)...)
	built = append(built,
		events.WithMaxReceiveCount(dlqObserveReceiveCount),
		events.WithDeadLetterHandler(DeadLetterHandler(queueName(queueURL), deps.Log)),
	)
	built = append(built, opts...)
	return events.NewSQSConsumerWithClient(cfg, deps.Client, processedHandler(deps, handler), built...)
}

// Keep a compile-time check that handlers still speak platform-events
// Envelope[json.RawMessage] — the same type org-membership's Handle takes.
var _ events.Handler = func(context.Context, events.Envelope[json.RawMessage]) error { return nil }

// dlqObserveReceiveCount is the ApproximateReceiveCount above which
// platform-events hands a delivery to DeadLetterHandler instead of the
// handler — one short of every queue's RedrivePolicy maxReceiveCount=5
// (api/asyncapi.yaml, scripts/init-localstack.sh). At 5 the dead-letter
// handler would never fire: SQS never makes a 6th delivery, it redrives
// after the 5th. So the handler sees deliveries 1-4 and DeadLetterHandler
// the 5th, just before SQS moves the message.
const dlqObserveReceiveCount = 4

// DeadLetterHandler logs a message's last delivery before SQS's own
// redrive moves it to the queue's DLQ — the first actionable signal, ahead
// of the DLQ-depth alert. Observability-only: it always returns an error,
// so platform-events never deletes the message and the move stays SQS's
// job (no application-level DLQ mechanism, §5).
func DeadLetterHandler(queue string, log Logger) events.Handler {
	return func(_ context.Context, env events.Envelope[json.RawMessage]) error {
		if log != nil {
			log.Error("message exhausted retries, SQS will move it to the DLQ — its cache eviction was never applied", map[string]interface{}{
				"queue": queue, "event_id": env.ID, "event_type": env.Type, "tenant_id": env.TenantID,
			})
		}
		return errors.New("dead-letter handler: observability-only, leaving the DLQ move to SQS's redrive policy")
	}
}

// queueName is the last path segment of an SQS queue URL.
func queueName(queueURL string) string {
	if i := strings.LastIndex(strings.TrimRight(queueURL, "/"), "/"); i >= 0 {
		return strings.TrimRight(queueURL, "/")[i+1:]
	}
	return queueURL
}

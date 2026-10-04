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
// DLQ handling (§5, LLD §16 AE-36): the DLQ is each queue's own RedrivePolicy
// target (Terraform in AWS, scripts/init-localstack.sh / init-floci.sh
// locally) — nothing here names or creates a DLQ. With Deps.DLQ set (always,
// in cmd/server), platform-events' WithDLQForwarding sends poison messages to
// that target itself, preserving the original body and attributes and
// deleting only after the send succeeds:
//
//   - a body that is not a valid envelope, or a Glue frame that fails to
//     decode — without forwarding, platform-events DELETES these, so the
//     eviction they carried would be lost with no trace in any DLQ;
//   - a message on its 5th delivery (after dlqObserveReceiveCount failures),
//     which DeadLetterHandler logs first. SQS's own redrive after the 5th
//     receive stays the backstop if a forward fails.
//
// Start also refuses a queue with no usable RedrivePolicy. There is still no
// replay mechanism (§5): a DLQ message is investigated and replayed by hand.
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
	// DLQ forwards poison messages to each queue's RedrivePolicy DLQ
	// (events.NewSQSDLQPublisherWithClient). nil — tests only — keeps the
	// older observe-only behaviour: malformed bodies are deleted and SQS's
	// redrive alone moves a message after its 5th delivery.
	DLQ events.DLQPublisher
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
// The env's MaxReceiveCount is ignored: the threshold is pinned to
// dlqObserveReceiveCount, one short of every queue's RedrivePolicy
// maxReceiveCount=5, and always paired with DeadLetterHandler (and
// WithDLQForwarding when deps.DLQ is set).
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
	// platform-events' GlueDecodeCodec strips the Glue wire header producers
	// add once their registry is configured (no Glue client or IAM
	// permission needed) and rejects a non-JSON payload with a clear error.
	// Decode only runs when Envelope.SchemaID is non-empty, so plain-JSON
	// envelopes pass through untouched. Same codec as iam-org-membership.
	// Without it the framed bytes reach every handler unstripped,
	// json.Unmarshal fails on every Glue-encoded event, and each one
	// dead-letters with its cache eviction never applied — for
	// TenderRestricted (ae:restricted has no TTL) indefinitely.
	built := []events.ConsumerOption{events.WithConsumerCodec(events.GlueDecodeCodec{})}
	built = append(built, config.SQSConsumerOptions(env)...)
	built = append(built,
		events.WithMaxReceiveCount(dlqObserveReceiveCount),
		events.WithDeadLetterHandler(DeadLetterHandler(queueName(queueURL), deps.Log, deps.DLQ != nil)),
	)
	if deps.DLQ != nil {
		built = append(built, events.WithDLQForwarding(deps.DLQ))
	}
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
// the 5th.
const dlqObserveReceiveCount = 4

// DeadLetterHandler logs a message's last delivery — the first actionable
// signal, ahead of the DLQ-depth alarm.
//
// With forwarding (a DLQ publisher is wired) it returns nil, which is what
// lets platform-events forward the message to the DLQ, delete it from the
// source queue and count it in platform_dlq_messages_total
// {reason="max_receive_count"}. Without forwarding it returns an error, so
// platform-events never deletes the message and SQS's redrive moves it.
func DeadLetterHandler(queue string, log Logger, forwarding bool) events.Handler {
	return func(_ context.Context, env events.Envelope[json.RawMessage]) error {
		if log != nil {
			log.Error("message exhausted retries, moving it to the DLQ — its cache eviction was never applied", map[string]interface{}{
				"queue": queue, "event_id": env.ID, "event_type": env.Type, "tenant_id": env.TenantID, "forwarded_by": dlqMover(forwarding),
			})
		}
		if forwarding {
			return nil
		}
		return errors.New("dead-letter handler: no DLQ publisher, leaving the DLQ move to SQS's redrive policy")
	}
}

func dlqMover(forwarding bool) string {
	if forwarding {
		return "platform-events"
	}
	return "sqs-redrive"
}

// NewDLQPublisher builds platform-events' SQS DLQ publisher. It resolves each
// queue's DLQ from that queue's own RedrivePolicy (cached, re-read on
// expiry), so the target can never drift from the infra-configured one.
// client is the plain *sqs.Client — it needs GetQueueAttributes on the
// source queues, and GetQueueUrl/SendMessage on their DLQs (deploy/iam).
func NewDLQPublisher(client events.DLQClientLike, consumerName string, log Logger) (events.DLQPublisher, error) {
	return events.NewSQSDLQPublisherWithClient(events.DLQConfig{
		ConsumerName: consumerName,
		Logger:       eventsLogger{log},
	}, client)
}

// queueName is the last path segment of an SQS queue URL.
func queueName(queueURL string) string {
	if i := strings.LastIndex(strings.TrimRight(queueURL, "/"), "/"); i >= 0 {
		return strings.TrimRight(queueURL, "/")[i+1:]
	}
	return queueURL
}

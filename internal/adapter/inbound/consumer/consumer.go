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

// glueStripCodec implements events.Codec for the consumer side only.
//
// Producers in this platform (Org & Membership, User Profile, Realm
// Provisioner) prepend an 18-byte AWS Glue Schema Registry header to the
// envelope's "data" field in production. platform-events v1.4.0 signals
// this via a non-empty "dataschema" field in the envelope, and calls
// Codec.Decode with the already-base64-decoded bytes. This codec strips the
// header and returns the plain JSON payload. Schema validation against the
// Glue registry is intentionally skipped — schemas are governed via
// asyncapi.yaml and tested through the existing handler unit tests.
//
// Encode is never called on a consumer-only service.
type glueStripCodec struct{}

const glueHeaderLen = 18
const glueMagicByte = byte(0x03)

func (glueStripCodec) Encode(_ context.Context, _ string, _ json.RawMessage) ([]byte, string, error) {
	return nil, "", fmt.Errorf("glueStripCodec: Encode not supported (consumer-only service)")
}

func (glueStripCodec) Decode(_ context.Context, _ string, encoded []byte) (json.RawMessage, error) {
	if len(encoded) < glueHeaderLen {
		return nil, fmt.Errorf("glueStripCodec: payload too short (%d bytes, need ≥%d for Glue header)", len(encoded), glueHeaderLen)
	}
	if encoded[0] != glueMagicByte {
		return nil, fmt.Errorf("glueStripCodec: unexpected magic byte 0x%02x (expected 0x%02x)", encoded[0], glueMagicByte)
	}
	return json.RawMessage(encoded[glueHeaderLen:]), nil
}

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

// ConsumerRecorder is the Tier 1 metrics port for SQS consumer instrumentation.
// Implementations emit platform_messages_received_total, platform_messages_processed_total,
// and platform_messages_failed_total with the queue label differentiating consumers.
type ConsumerRecorder interface {
	ObserveMessageReceived(queue string)
	ObserveMessageProcessed(queue string)
	ObserveMessageFailed(queue string)
}

// NoopConsumerRecorder implements ConsumerRecorder with no side effects.
// Used when Deps.Metrics is nil (e.g. in tests that don't need consumer metrics).
type NoopConsumerRecorder struct{}

func (NoopConsumerRecorder) ObserveMessageReceived(string)  {}
func (NoopConsumerRecorder) ObserveMessageProcessed(string) {}
func (NoopConsumerRecorder) ObserveMessageFailed(string)    {}

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
	Metrics     ConsumerRecorder
	Invalidator *usecase.Invalidator
}

// recorder returns Deps.Metrics if set, otherwise a no-op recorder. This
// allows tests that don't care about consumer metrics to leave Metrics nil
// without panicking.
func (d Deps) recorder() ConsumerRecorder {
	if d.Metrics == nil {
		return NoopConsumerRecorder{}
	}
	return d.Metrics
}

// idleConsumer is a no-op Consumer used when a queue URL is unconfigured —
// same MVP-idle pattern as iam-user-profile's consumer wiring, useful for
// partial local dev setups that don't run all five queues.
type idleConsumer struct{}

func (idleConsumer) Start(context.Context) error { return nil }
func (idleConsumer) Stop() error                 { return nil }

// dedupingHandler wraps handler with the §5 idempotency check: a message
// whose event ID has already been marked processed is acknowledged
// (deleted) without being handled again. queueName is the metric label value
// emitted on platform_messages_* counters.
func dedupingHandler(deps Deps, queueName string, handler events.Handler) events.Handler {
	rec := deps.recorder()
	return func(ctx context.Context, env events.Envelope[json.RawMessage]) error {
		rec.ObserveMessageReceived(queueName)

		first, err := deps.Cache.MarkProcessed(ctx, env.ID)
		if err != nil {
			// Valkey is unavailable for the dedup check — process anyway
			// rather than block eviction on a soft dependency. At worst this
			// re-applies an idempotent eviction, never a correctness issue.
			deps.Log.Warn("idempotency check failed, processing anyway", map[string]interface{}{
				"error": err.Error(), "event_id": env.ID, "event_type": env.Type,
			})
			if handlerErr := handler(ctx, env); handlerErr != nil {
				rec.ObserveMessageFailed(queueName)
				return handlerErr
			}
			rec.ObserveMessageProcessed(queueName)
			return nil
		}
		if !first {
			rec.ObserveMessageProcessed(queueName) // duplicate — acked, not retried
			return nil
		}
		if handlerErr := handler(ctx, env); handlerErr != nil {
			if evictErr := deps.Cache.EvictProcessed(ctx, env.ID); evictErr != nil {
				deps.Log.Warn("failed to evict idempotency marker after handler error", map[string]interface{}{
					"error": evictErr.Error(), "event_id": env.ID, "event_type": env.Type,
				})
			}
			rec.ObserveMessageFailed(queueName)
			return handlerErr
		}
		rec.ObserveMessageProcessed(queueName)
		return nil
	}
}

// buildConsumer constructs an SQS consumer for queueURL, or an idleConsumer
// if queueURL is empty. queueName is the canonical label value for
// platform_messages_* metrics. opts passes through to events.NewSQSConsumerWithClient
// — mainly used by tests to tune WithVisibilityTimeout for a fast DLQ cycle.
//
// glueStripCodec is always registered so that messages from producers that
// use AWS Glue Schema Registry encoding (non-empty "dataschema" envelope
// field) are decoded correctly in production. Messages without a "dataschema"
// field (dev/test, NoopCodec producers) bypass the codec entirely.
func buildConsumer(queueURL, queueName string, deps Deps, handler events.Handler, opts ...events.ConsumerOption) (events.Consumer, error) {
	if queueURL == "" {
		return idleConsumer{}, nil
	}
	u, err := url.ParseRequestURI(queueURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("sqs: queue URL %q must be an http or https URL", queueURL)
	}
	allOpts := append([]events.ConsumerOption{events.WithConsumerCodec(glueStripCodec{})}, opts...)
	return events.NewSQSConsumerWithClient(events.SQSConfig{
		QueueURL:    queueURL,
		Region:      deps.Region,
		EndpointURL: deps.EndpointURL,
		MaxMessages: 10,
		WaitSeconds: 20,
		Logger:      deps.Log,
	}, deps.Client, dedupingHandler(deps, queueName, handler), allOpts...)
}

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
// the "special-case DLQ-replay mechanism" §5 says not to build.
package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/config"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/events"

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
// MaxReceiveCount is forced to 0: this service's DLQ is SQS-native redrive
// on the queue resource. Passing SQS_MAX_RECEIVE_COUNT through
// SQSConsumerOptions would make platform-events delete the message in-process
// instead of leaving it for the queue's RedrivePolicy.
//
// opts passes through to events.NewSQSConsumerWithClient — mainly used by
// tests to tune WithVisibilityTimeout for a fast DLQ cycle, and by
// cmd/server for per-queue WithConcurrency.
func buildConsumer(queueURL string, deps Deps, handler events.Handler, opts ...events.ConsumerOption) (events.Consumer, error) {
	if queueURL == "" {
		return idleConsumer{}, nil
	}
	if u, err := url.ParseRequestURI(queueURL); err != nil || u.Scheme == "" {
		return nil, fmt.Errorf("invalid queue URL %q: must be an absolute URL with a scheme", queueURL)
	}
	env := deps.SQS
	env.QueueURL = queueURL
	env.MaxReceiveCount = 0
	cfg := config.SQSConfigFromEnv(env, eventsLogger{deps.Log})
	// NoopCodec is the identity events.Codec siblings pass when Glue is
	// unset (WithConsumerCodec). Decode only runs when Envelope.SchemaID
	// is non-empty; inbound IAM events are plain JSON, so this is the
	// library hook with no wire-format change.
	built := []events.ConsumerOption{events.WithConsumerCodec(events.NoopCodec{})}
	built = append(built, config.SQSConsumerOptions(env)...)
	built = append(built, opts...)
	return events.NewSQSConsumerWithClient(cfg, deps.Client, processedHandler(deps, handler), built...)
}

// Keep a compile-time check that handlers still speak platform-events
// Envelope[json.RawMessage] — the same type org-membership's Handle takes.
var _ events.Handler = func(context.Context, events.Envelope[json.RawMessage]) error { return nil }

package consumer

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/events"
)

// ConsumerName is the (event_id, consumer) key component in processed_events
// — same PE-1 identity org-membership uses so every queue this process
// consumes shares one dedup ledger. platform-events requires Envelope.ID
// idempotency; this is that ledger.
const ConsumerName = "iam-authz-enrichment"

// IdempotencyStore is the processed_events port, named and shaped to
// mirror iam-org-membership's / iam-user-profile's port.IdempotencyStore.
//
// Those services persist to a Postgres processed_events table via
// INSERT … ON CONFLICT DO NOTHING inside a transaction. This service has
// no database (HLD §5.4 / LLD AE-6), so the Valkey adapter satisfies the
// same port with SET NX on ae:processed:{event_id} — functionally the
// platform-events processed_events pattern, substituted because there is
// no table to hold it in.
//
// Mark-then-handle (not mark-last): a handler failure Evicts the claim so
// SQS redelivery is a real retry and the message can still reach the
// SQS-native DLQ after maxReceiveCount, rather than being silently
// swallowed as "already processed". skipDuplicate's MarkProcessed SET NX
// is itself the duplicate check — there is no separate IsProcessed method.
type IdempotencyStore interface {
	MarkProcessed(ctx context.Context, consumer, eventID string) (bool, error)
	EvictProcessed(ctx context.Context, consumer, eventID string) error
}

// processedHandler wraps handler with the platform-events processed_events
// contract: Envelope.ID is the idempotency key (skipDuplicate / mark-first
// SET NX). A redelivered ID is acknowledged without being handled again;
// a handler error releases the claim so the next delivery retries.
func processedHandler(deps Deps, handler events.Handler) events.Handler {
	return func(ctx context.Context, env events.Envelope[json.RawMessage]) error {
		if env.ID == "" {
			return fmt.Errorf("envelope missing id")
		}

		skip, err := skipDuplicate(ctx, deps.Cache, env.ID)
		if err != nil {
			// Dedup store unavailable — process anyway rather than block
			// eviction on a soft dependency. At worst this re-applies an
			// idempotent cache eviction.
			deps.Log.Warn("idempotency check failed, processing anyway", map[string]interface{}{
				"error": err.Error(), "event_id": env.ID, "event_type": env.Type,
			})
			return handler(ctx, env)
		}
		if skip {
			return nil
		}
		// A handler panic must evict the just-claimed marker before
		// propagating, the same as a returned error does below — otherwise
		// the message is left permanently "processed" and any redelivery is
		// silently skipped. This matters most for tender-authz-q's
		// TenderRestricted: ae:restricted has no TTL (unlike every other
		// queue's evictions, which self-heal within their cache's TTL), so a
		// panic there would disable the tender-ACL overlay for that tender
		// indefinitely with no automatic recovery. Re-panics afterward so
		// platform-events' own top-level panic recovery still runs exactly
		// as it would without this defer.
		defer func() {
			if r := recover(); r != nil {
				if evictErr := deps.Cache.EvictProcessed(ctx, ConsumerName, env.ID); evictErr != nil {
					deps.Log.Warn("failed to evict idempotency marker after handler panic", map[string]interface{}{
						"error": evictErr.Error(), "event_id": env.ID, "event_type": env.Type,
					})
				}
				panic(r)
			}
		}()
		if handlerErr := handler(ctx, env); handlerErr != nil {
			if evictErr := deps.Cache.EvictProcessed(ctx, ConsumerName, env.ID); evictErr != nil {
				deps.Log.Warn("failed to evict idempotency marker after handler error", map[string]interface{}{
					"error": evictErr.Error(), "event_id": env.ID, "event_type": env.Type,
				})
			}
			return handlerErr
		}
		return nil
	}
}

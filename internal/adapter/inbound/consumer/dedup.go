package consumer

import (
	"context"
	"encoding/json"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/events"
)

// skipDuplicate is the processed_events probe every inbound handler runs
// before work — same helper name and Envelope.ID contract as
// iam-org-membership / iam-user-profile's consumer/dedup.go.
//
// platform-events has no processed-events API. The library's documented
// consumer pattern is Envelope.ID + INSERT ON CONFLICT DO NOTHING; those
// siblings persist that to a Postgres processed_events table. This
// service has no database (HLD §5.4 / LLD AE-6), so MarkProcessed is
// Valkey SET NX on ae:processed:{event_id} — the atomic claim *is* the
// duplicate check (no separate IsProcessed step).
//
// A hit (already claimed) short-circuits. A store error is returned so
// processedHandler can fail-open and still run the inner handler rather
// than block cache eviction on a soft dependency.
func skipDuplicate(ctx context.Context, store IdempotencyStore, eventID string) (skip bool, err error) {
	first, err := store.MarkProcessed(ctx, ConsumerName, eventID)
	if err != nil {
		return false, err
	}
	return !first, nil
}

// ackUnknown is the forward-compat path siblings use for an event type
// with no wired handler: log and acknowledge so SQS does not redeliver
// the same unknown type. The processedHandler wrapper has already
// claimed Envelope.ID (mark-first SET NX); this helper does not mark
// again and has no TxRunner — there is no processed_events row to join
// with a local write.
func ackUnknown(log Logger, env events.Envelope[json.RawMessage]) error {
	if log != nil {
		log.Info("unknown event type — silently acknowledging", map[string]interface{}{
			"event_id": env.ID, "event_type": env.Type,
		})
	}
	return nil
}

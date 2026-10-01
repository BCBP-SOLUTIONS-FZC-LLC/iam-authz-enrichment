package consumer

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/test/fixtures"
)

func TestSkipDuplicate_FirstDelivery_DoesNotSkip(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()

	skip, err := skipDuplicate(context.Background(), cache, "evt-1")

	require.NoError(t, err)
	assert.False(t, skip)
}

func TestSkipDuplicate_Redelivery_Skips(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	_, err := cache.MarkProcessed(context.Background(), ConsumerName, "evt-1")
	require.NoError(t, err)

	skip, err := skipDuplicate(context.Background(), cache, "evt-1")

	require.NoError(t, err)
	assert.True(t, skip)
}

func TestSkipDuplicate_StoreError_ReturnsError(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.MarkProcessedErr = assert.AnError

	skip, err := skipDuplicate(context.Background(), cache, "evt-1")

	require.Error(t, err)
	assert.False(t, skip, "a store error must not look like a duplicate hit")
}

func TestAckUnknown_LogsAndAcks(t *testing.T) {
	t.Parallel()
	rec := &recordingLogger{}
	env := events.Envelope[json.RawMessage]{ID: "evt-1", Type: "FutureEvent"}

	err := ackUnknown(rec, env)

	require.NoError(t, err)
	require.Len(t, rec.infos, 1)
	assert.Contains(t, rec.infos[0], "unknown event type")
}

func TestAckUnknown_NilLogger(t *testing.T) {
	t.Parallel()
	assert.NoError(t, ackUnknown(nil, events.Envelope[json.RawMessage]{Type: "X"}))
}

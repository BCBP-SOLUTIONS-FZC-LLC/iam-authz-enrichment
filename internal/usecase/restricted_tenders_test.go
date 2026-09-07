package usecase_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/test/fixtures"
)

func TestRestrictedTenderSet_StoreVisibleToOtherReplica(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := fixtures.NewFakeCache()
	writer := usecase.NewRestrictedTenderSet(5 * time.Second)
	writer.BindStore(store)
	reader := usecase.NewRestrictedTenderSet(5 * time.Second)
	reader.BindStore(store)

	require.NoError(t, writer.MarkRestricted(ctx, "tenant-1", "tender-9"))
	assert.True(t, reader.IsRestricted(ctx, "tenant-1", "tender-9"))
}

func TestRestrictedTenderSet_StoreErrorOnMark_DoesNotWriteLocal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := fixtures.NewFakeCache()
	store.SetRestrictedErr = assert.AnError
	s := usecase.NewRestrictedTenderSet(5 * time.Second)
	s.BindStore(store)

	require.Error(t, s.MarkRestricted(ctx, "tenant-1", "tender-9"))
	assert.False(t, s.IsRestricted(ctx, "tenant-1", "tender-9"))
}

func TestRestrictedTenderSet_StoreErrorOnGet_TreatedAsNotRestricted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := fixtures.NewFakeCache()
	store.RestrictedErr = assert.AnError
	s := usecase.NewRestrictedTenderSet(5 * time.Second)
	s.BindStore(store)

	assert.False(t, s.IsRestricted(ctx, "tenant-1", "tender-9"))
}

func TestRestrictedTenderSet_StoreErrorOnGet_NotCached_RetriesNextCall(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := fixtures.NewFakeCache()
	store.RestrictedErr = assert.AnError
	// A long negTTL: if the error were wrongly cached as a confirmed
	// negative, the second call below would be served from L1 instead of
	// retrying the store.
	s := usecase.NewRestrictedTenderSet(5 * time.Second)
	s.BindStore(store)

	assert.False(t, s.IsRestricted(ctx, "tenant-1", "tender-9"))
	assert.False(t, s.IsRestricted(ctx, "tenant-1", "tender-9"))

	assert.Equal(t, []string{"GetRestricted:tenant-1:tender-9", "GetRestricted:tenant-1:tender-9"}, store.SortedCalls(),
		"a transient store error must not be cached as a confirmed negative — every call must retry the store, not wait out negTTL")
}

func TestRestrictedTenderSet_NegativeCache_ServedFromL1UntilTTLExpires(t *testing.T) {
	ctx := context.Background()
	store := fixtures.NewFakeCache()
	s := usecase.NewRestrictedTenderSet(20 * time.Millisecond)
	s.BindStore(store)

	assert.False(t, s.IsRestricted(ctx, "tenant-1", "tender-9"), "first call misses L1, queries store, caches negative")

	require.NoError(t, store.SetRestricted(ctx, "tenant-1", "tender-9"))
	assert.False(t, s.IsRestricted(ctx, "tenant-1", "tender-9"), "still within negTTL — served from L1 without re-checking the store")

	time.Sleep(30 * time.Millisecond)
	assert.True(t, s.IsRestricted(ctx, "tenant-1", "tender-9"), "negTTL elapsed — re-checks the store and observes the other replica's flip")
}

// blockingGetRestrictedCache lets a test pause IsRestricted mid-flight,
// inside its store.GetRestricted call, to deterministically land a
// concurrent MarkRestricted before the stale GetRestricted result returns.
type blockingGetRestrictedCache struct {
	*fixtures.FakeCache
	started chan struct{}
	resume  chan struct{}
}

func (c *blockingGetRestrictedCache) GetRestricted(context.Context, string, string) (bool, error) {
	close(c.started)
	<-c.resume
	return false, nil // stale: the store hadn't observed the concurrent write yet
}

func TestRestrictedTenderSet_ConcurrentMarkDuringStaleLookup_DoesNotClobber(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cache := &blockingGetRestrictedCache{
		FakeCache: fixtures.NewFakeCache(),
		started:   make(chan struct{}),
		resume:    make(chan struct{}),
	}
	s := usecase.NewRestrictedTenderSet(5 * time.Second)
	s.BindStore(cache)

	result := make(chan bool, 1)
	go func() { result <- s.IsRestricted(ctx, "tenant-1", "tender-9") }()

	<-cache.started
	require.NoError(t, s.MarkRestricted(ctx, "tenant-1", "tender-9"))
	close(cache.resume)

	assert.True(t, <-result, "a MarkRestricted landing while a stale GetRestricted is in flight must win, not be clobbered by the stale negative")
	assert.True(t, s.IsRestricted(ctx, "tenant-1", "tender-9"), "the positive entry must stick after the race")
}

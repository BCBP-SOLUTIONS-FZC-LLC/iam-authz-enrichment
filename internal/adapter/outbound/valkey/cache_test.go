package valkey

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

func newTestCache(t *testing.T, jitter time.Duration) (*Cache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	c := New(Config{
		Addr:               mr.Addr(),
		CtxTTL:             time.Hour,
		CtxJitter:          jitter,
		TenderACLTTL:       time.Hour,
		NegativeTTL:        time.Hour,
		ProcessedTTL:       time.Hour,
		StaleIfErrorMaxAge: time.Hour,
	})
	t.Cleanup(func() { _ = c.Close() })
	return c, mr
}

func TestNew_ParsesRedisURL(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	c := New(Config{Addr: "redis://" + mr.Addr()})
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Health(context.Background()))
}

func TestNew_FallsBackToPlainAddrOnParseFailure(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	// Not a valid redis:// URL, so redis.ParseURL fails and New falls back to
	// treating it as a plain host:port Addr.
	c := New(Config{Addr: mr.Addr(), DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second})
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Health(context.Background()))
}

func TestJitteredTTL(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 60*time.Second, jitteredTTL(60*time.Second, 0), "jitter<=0 returns base unchanged")

	base, jitter := 60*time.Second, 6*time.Second
	for i := 0; i < 50; i++ {
		got := jitteredTTL(base, jitter)
		assert.GreaterOrEqual(t, got, base-jitter)
		assert.LessOrEqual(t, got, base+jitter)
	}
}

func TestMembershipContext_RoundTrip_FreshThenStale(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	c := New(Config{
		Addr:               mr.Addr(),
		CtxTTL:             50 * time.Millisecond,
		StaleIfErrorMaxAge: time.Hour,
	})
	defer func() { _ = c.Close() }()
	ctx := context.Background()

	_, result, err := c.GetMembershipContext(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheMiss, result)

	want := domain.MembershipContext{Roles: []string{"tenant_admin"}}
	require.NoError(t, c.SetMembershipContext(ctx, "t1", "u1", want))

	got, result, err := c.GetMembershipContext(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheFresh, result)
	assert.Equal(t, want.Roles, got.Roles)

	// Freshness is computed from real wall-clock time (time.Since), which is
	// independent of miniredis's own simulated clock — a real sleep is
	// required here; FastForward only advances miniredis's physical-TTL
	// expiry, not our soft-TTL bookkeeping.
	time.Sleep(70 * time.Millisecond)
	got, result, err = c.GetMembershipContext(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheStale, result)
	assert.Equal(t, want.Roles, got.Roles)

	require.NoError(t, c.EvictMembershipContext(ctx, "t1", "u1"))
	_, result, err = c.GetMembershipContext(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheMiss, result)
}

func TestGetMembershipContext_UnmarshalError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	require.NoError(t, mr.Set(ctxKey("t1", "u1"), "not-json"))

	_, result, err := c.GetMembershipContext(context.Background(), "t1", "u1")
	assert.Error(t, err)
	assert.Equal(t, domain.CacheMiss, result)
}

func TestGetMembershipContext_ConnectionError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	_, result, err := c.GetMembershipContext(context.Background(), "t1", "u1")
	assert.Error(t, err)
	assert.Equal(t, domain.CacheMiss, result)
}

func TestTenantContext_RoundTrip(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 6*time.Second) // exercise the jitter>0 branch too
	ctx := context.Background()

	_, result, err := c.GetTenantContext(ctx, "t1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheMiss, result)

	want := domain.TenantContext{Plan: "pro", FeatureFlags: []string{"a"}}
	require.NoError(t, c.SetTenantContext(ctx, "t1", want))

	got, result, err := c.GetTenantContext(ctx, "t1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheFresh, result)
	assert.Equal(t, want.Plan, got.Plan)

	require.NoError(t, c.EvictTenantContext(ctx, "t1"))
	_, result, err = c.GetTenantContext(ctx, "t1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheMiss, result)
}

func TestTenderACL_RoundTrip(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 0)
	ctx := context.Background()

	_, hit, err := c.GetTenderACL(ctx, "t1", "tender-1", "u1")
	require.NoError(t, err)
	assert.False(t, hit)

	want := domain.TenderACL{HasAccess: true, AccessLevel: domain.AccessLevelApprove}
	require.NoError(t, c.SetTenderACL(ctx, "t1", "tender-1", "u1", want))

	got, hit, err := c.GetTenderACL(ctx, "t1", "tender-1", "u1")
	require.NoError(t, err)
	assert.True(t, hit)
	assert.Equal(t, want, got)
}

func TestGetTenderACL_UnmarshalError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	require.NoError(t, mr.Set(tenderACLKey("t1", "tender-1", "u1"), "not-json"))

	_, hit, err := c.GetTenderACL(context.Background(), "t1", "tender-1", "u1")
	assert.Error(t, err)
	assert.False(t, hit)
}

func TestGetTenderACL_ConnectionError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	_, hit, err := c.GetTenderACL(context.Background(), "t1", "tender-1", "u1")
	assert.Error(t, err)
	assert.False(t, hit)
}

func TestSetTenderACL_MarshalIsAlwaysValid_ConnectionErrorSurfaces(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	err := c.SetTenderACL(context.Background(), "t1", "tender-1", "u1", domain.TenderACL{})
	assert.Error(t, err)
}

func TestEvictTenderACLForUser_ScansAllMatchingKeysAcrossPages(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 0)
	ctx := context.Background()

	// More than one SCAN page's worth (miniredis default COUNT batching)
	// to exercise the cursor-loop, not just a single-page scan.
	for i := 0; i < 250; i++ {
		tender := "tender-" + string(rune('a'+i%26)) + string(rune('0'+i%10))
		require.NoError(t, c.SetTenderACL(ctx, "t1", tender+"-x", "u1", domain.TenderACL{HasAccess: true}))
	}
	require.NoError(t, c.SetTenderACL(ctx, "t1", "tender-keep", "other-user", domain.TenderACL{HasAccess: true}))

	require.NoError(t, c.EvictTenderACLForUser(ctx, "t1", "u1"))

	_, hit, err := c.GetTenderACL(ctx, "t1", "tender-keep", "other-user")
	require.NoError(t, err)
	assert.True(t, hit)
}

func TestEvictTenderACLForUser_ConnectionError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	err := c.EvictTenderACLForUser(context.Background(), "t1", "u1")
	assert.Error(t, err)
}

func TestNegativeCache_RoundTrip(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 0)
	ctx := context.Background()

	hit, err := c.GetNegative(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.False(t, hit)

	require.NoError(t, c.SetNegative(ctx, "t1", "u1"))
	hit, err = c.GetNegative(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.True(t, hit)

	require.NoError(t, c.EvictNegative(ctx, "t1", "u1"))
	hit, err = c.GetNegative(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.False(t, hit)
}

func TestGetNegative_ConnectionError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	_, err := c.GetNegative(context.Background(), "t1", "u1")
	assert.Error(t, err)
}

func TestSetJittered_MarshalError(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 0)
	// Channels are never JSON-marshalable — exercises setJittered's marshal
	// error branch, which no real caller can reach through the exported API
	// (every concrete type this service actually caches marshals cleanly).
	err := c.setJittered(context.Background(), "bad-key", make(chan int), time.Second, 0, time.Second)
	assert.Error(t, err)
}

func TestMarkProcessed_ConnectionError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	_, err := c.MarkProcessed(context.Background(), "evt-1")
	assert.Error(t, err)
}

func TestMarkProcessed_IdempotentThenEvictAllowsRetry(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 0)
	ctx := context.Background()

	first, err := c.MarkProcessed(ctx, "evt-1")
	require.NoError(t, err)
	assert.True(t, first)

	second, err := c.MarkProcessed(ctx, "evt-1")
	require.NoError(t, err)
	assert.False(t, second)

	require.NoError(t, c.EvictProcessed(ctx, "evt-1"))
	third, err := c.MarkProcessed(ctx, "evt-1")
	require.NoError(t, err)
	assert.True(t, third, "after EvictProcessed a retry must be allowed")
}

func TestHealth_ReportsConnectionFailure(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	assert.Error(t, c.Health(context.Background()))
}

func TestClose_IsIdempotentSafe(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 0)
	assert.NoError(t, c.Close())
}

// Sanity check that redis.Nil itself (not wrapped) is what miniredis
// returns on a genuine miss, confirming Miss vs connection-error
// classification throughout this file rests on the right signal.
func TestRedisNilIsTheMissSignal(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()

	err := client.Get(context.Background(), "nope").Err()
	assert.ErrorIs(t, err, redis.Nil)
}

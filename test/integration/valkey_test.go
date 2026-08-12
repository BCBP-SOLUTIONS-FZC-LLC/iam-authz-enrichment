//go:build integration

// Package integration exercises this service's outbound adapters against
// real Valkey + LocalStack SQS (docker compose up valkey localstack),
// complementing the fake-backed unit suite in internal/... — see §12's
// build-order step 8.
package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/outbound/valkey"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

func valkeyAddr() string {
	if v := os.Getenv("VALKEY_URL"); v != "" {
		return v
	}
	return "localhost:6379"
}

func newTestCache(t *testing.T) *valkey.Cache {
	t.Helper()
	c := valkey.New(valkey.Config{
		Addr:               valkeyAddr(),
		CtxTTL:             300 * time.Millisecond,
		CtxJitter:          0,
		TenderACLTTL:       200 * time.Millisecond,
		NegativeTTL:        150 * time.Millisecond,
		ProcessedTTL:       time.Minute,
		StaleIfErrorMaxAge: time.Second,
	})
	require.NoError(t, c.Health(context.Background()), "Valkey must be reachable — run `docker compose up -d valkey`")
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestValkey_MembershipContext_RoundTrip_ThenExpires(t *testing.T) {
	ctx := context.Background()
	cache := newTestCache(t)
	tenant, user := "it-tenant-1", "it-user-1"
	defer func() { _ = cache.EvictMembershipContext(ctx, tenant, user) }()

	_, result, err := cache.GetMembershipContext(ctx, tenant, user)
	require.NoError(t, err)
	assert.Equal(t, domain.CacheMiss, result)

	want := domain.MembershipContext{Roles: []string{"tenant_admin"}, Departments: []domain.Department{}, Delegations: []domain.Delegation{}}
	require.NoError(t, cache.SetMembershipContext(ctx, tenant, user, want))

	got, result, err := cache.GetMembershipContext(ctx, tenant, user)
	require.NoError(t, err)
	assert.Equal(t, domain.CacheFresh, result)
	assert.Equal(t, want.Roles, got.Roles)

	// Past the 300ms soft TTL, still within the physical TTL (soft + 1s
	// grace) — must report Stale, not Miss.
	time.Sleep(400 * time.Millisecond)
	got, result, err = cache.GetMembershipContext(ctx, tenant, user)
	require.NoError(t, err)
	assert.Equal(t, domain.CacheStale, result)
	assert.Equal(t, want.Roles, got.Roles, "the value itself must still be readable while stale")
}

func TestValkey_NegativeCache_ExpiresIndependently(t *testing.T) {
	ctx := context.Background()
	cache := newTestCache(t)
	tenant, user := "it-tenant-2", "it-user-2"
	defer func() { _ = cache.EvictNegative(ctx, tenant, user) }()

	hit, err := cache.GetNegative(ctx, tenant, user)
	require.NoError(t, err)
	assert.False(t, hit)

	require.NoError(t, cache.SetNegative(ctx, tenant, user))
	hit, err = cache.GetNegative(ctx, tenant, user)
	require.NoError(t, err)
	assert.True(t, hit)

	time.Sleep(200 * time.Millisecond) // past the 150ms negative TTL
	hit, err = cache.GetNegative(ctx, tenant, user)
	require.NoError(t, err)
	assert.False(t, hit, "the negative sentinel must actually expire off Valkey, not just logically")
}

func TestValkey_EvictTenderACLForUser_ScansAcrossTenders(t *testing.T) {
	ctx := context.Background()
	cache := newTestCache(t)
	tenant, user := "it-tenant-3", "it-user-3"

	for _, tender := range []string{"tender-a", "tender-b"} {
		require.NoError(t, cache.SetTenderACL(ctx, tenant, tender, user, domain.TenderACL{HasAccess: true, AccessLevel: domain.AccessLevelView}))
	}
	// A different user's grant on the same tenant/tender must survive.
	require.NoError(t, cache.SetTenderACL(ctx, tenant, "tender-a", "other-user", domain.TenderACL{HasAccess: true, AccessLevel: domain.AccessLevelView}))

	require.NoError(t, cache.EvictTenderACLForUser(ctx, tenant, user))

	for _, tender := range []string{"tender-a", "tender-b"} {
		_, hit, err := cache.GetTenderACL(ctx, tenant, tender, user)
		require.NoError(t, err)
		assert.False(t, hit, "tender %s must have been evicted for the deleted user", tender)
	}
	_, hit, err := cache.GetTenderACL(ctx, tenant, "tender-a", "other-user")
	require.NoError(t, err)
	assert.True(t, hit, "eviction must be scoped to the deleted user only")
}

func TestValkey_MarkProcessed_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	cache := newTestCache(t)
	// A fresh ID per run — ae:processed has a 7-day TTL, so a hardcoded literal
	// would only pass the first time against a long-lived local Valkey instance.
	eventID := uuid.NewString()

	first, err := cache.MarkProcessed(ctx, eventID)
	require.NoError(t, err)
	assert.True(t, first)

	second, err := cache.MarkProcessed(ctx, eventID)
	require.NoError(t, err)
	assert.False(t, second, "SET NX must reject the second mark for the same event ID")
}

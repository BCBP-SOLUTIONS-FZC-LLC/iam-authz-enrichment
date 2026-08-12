package usecase_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/test/fixtures"
)

// One test per §5 event type, asserting the *correct* key (or tenant-scoped
// slice) is evicted and nothing else.

func TestInvalidator_MembershipEvent_EvictsCtxAndNegative(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})

	err := inv.HandleMembershipEvent(context.Background(), "tenant-1", usecase.MembershipEventPayload{UserID: "alice"})

	require.NoError(t, err)
	assert.Equal(t, []string{
		"EvictMembershipContext:tenant-1:alice",
		"EvictNegative:tenant-1:alice",
	}, cache.SortedCalls())
}

func TestInvalidator_MembershipEvent_EvictCtxError_Propagates(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictCtxErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})

	err := inv.HandleMembershipEvent(context.Background(), "tenant-1", usecase.MembershipEventPayload{UserID: "alice"})

	require.Error(t, err)
}

func TestInvalidator_MembershipEvent_EvictNegError_Propagates(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictNegErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})

	err := inv.HandleMembershipEvent(context.Background(), "tenant-1", usecase.MembershipEventPayload{UserID: "alice"})

	require.Error(t, err)
}

func TestInvalidator_UserUpdated_OnlyEvictsOnEmailChange(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})

	err := inv.HandleUserUpdated(context.Background(), "tenant-1", usecase.UserEventPayload{
		UserID: "alice", ChangedFields: []string{"display_name"},
	})
	require.NoError(t, err)
	assert.Empty(t, cache.SortedCalls(), "a non-email change must be a no-op (§5)")

	err = inv.HandleUserUpdated(context.Background(), "tenant-1", usecase.UserEventPayload{
		UserID: "alice", ChangedFields: []string{"display_name", "email"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"EvictMembershipContext:tenant-1:alice",
		"EvictNegative:tenant-1:alice",
	}, cache.SortedCalls())
}

func TestInvalidator_UserAvailabilityChanged_Evicts(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})

	err := inv.HandleUserAvailabilityChanged(context.Background(), "tenant-1", usecase.UserEventPayload{UserID: "alice"})

	require.NoError(t, err)
	assert.Equal(t, []string{
		"EvictMembershipContext:tenant-1:alice",
		"EvictNegative:tenant-1:alice",
	}, cache.SortedCalls())
}

func TestInvalidator_UserAvailabilityChanged_EvictCtxError_Propagates(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictCtxErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})

	err := inv.HandleUserAvailabilityChanged(context.Background(), "tenant-1", usecase.UserEventPayload{UserID: "alice"})

	require.Error(t, err)
}

func TestInvalidator_UserAvailabilityChanged_EvictNegError_Propagates(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictNegErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})

	err := inv.HandleUserAvailabilityChanged(context.Background(), "tenant-1", usecase.UserEventPayload{UserID: "alice"})

	require.Error(t, err)
}

func TestInvalidator_UserDeleted_EvictCtxError_ShortCircuitsBeforeTenderACL(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictCtxErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})

	err := inv.HandleUserDeleted(context.Background(), "tenant-1", usecase.UserEventPayload{UserID: "alice"})

	require.Error(t, err)
	assert.NotContains(t, cache.SortedCalls(), "EvictTenderACLForUser:tenant-1:alice")
}

func TestInvalidator_UserDeleted_TenderACLEvictionFails_BestEffortDoesNotPropagate(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictTenderACLErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})

	err := inv.HandleUserDeleted(context.Background(), "tenant-1", usecase.UserEventPayload{UserID: "alice"})

	require.NoError(t, err, "§5: the tender-ACL eviction is best-effort — its failure must not fail the whole event")
}

func TestInvalidator_UserDeleted_EvictsCtxNegativeAndTenderACL(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})

	err := inv.HandleUserDeleted(context.Background(), "tenant-1", usecase.UserEventPayload{UserID: "alice"})

	require.NoError(t, err)
	assert.Equal(t, []string{
		"EvictMembershipContext:tenant-1:alice",
		"EvictNegative:tenant-1:alice",
		"EvictTenderACLForUser:tenant-1:alice",
	}, cache.SortedCalls())
}

func TestInvalidator_BillingEvent_EvictsTenantSliceOnly(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})

	err := inv.HandleBillingEvent(context.Background(), "tenant-1")

	require.NoError(t, err)
	assert.Equal(t, []string{"EvictTenantContext:tenant-1"}, cache.SortedCalls(),
		"a tenant-wide billing event must be a single-key eviction, never touching per-user ae:ctx")
}

func TestInvalidator_TenantConverted_EvictsTenantSliceAndRefreshesRealmMap(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	realmMap := usecase.NewRealmMap(nil)
	inv := usecase.NewInvalidator(cache, realmMap, usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})

	err := inv.HandleTenantConverted(context.Background(), "tenant-1", usecase.TenantRealmEventPayload{Realm: "realm-1"})

	require.NoError(t, err)
	assert.Equal(t, []string{"EvictTenantContext:tenant-1"}, cache.SortedCalls())
	tenant, ok := realmMap.Lookup("realm-1")
	assert.True(t, ok)
	assert.Equal(t, "tenant-1", tenant)
}

func TestInvalidator_TenantRealmReady_RefreshesRealmMapOnly_NoEviction(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	realmMap := usecase.NewRealmMap(nil)
	inv := usecase.NewInvalidator(cache, realmMap, usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})

	inv.HandleTenantRealmReady("tenant-direct-paid", usecase.TenantRealmEventPayload{Realm: "realm-direct-paid"})

	assert.Empty(t, cache.SortedCalls(), "§5: TenantRealmReady must NOT evict ae:ctx")
	tenant, ok := realmMap.Lookup("realm-direct-paid")
	assert.True(t, ok, "the direct-paid-signup case: only TenantRealmReady fires, and it must still update the realm map")
	assert.Equal(t, "tenant-direct-paid", tenant)
}

func TestInvalidator_TenderRestricted_FlipsInMemoryFact_NoEviction(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	restricted := usecase.NewRestrictedTenderSet()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), restricted, fixtures.NoopLogger{})

	assert.False(t, restricted.IsRestricted("tenant-1", "tender-9"))
	inv.HandleTenderRestricted("tenant-1", usecase.TenderRestrictedPayload{TenderID: "tender-9"})

	assert.Empty(t, cache.SortedCalls(), "§5: TenderRestricted is not a cache eviction")
	assert.True(t, restricted.IsRestricted("tenant-1", "tender-9"))
	assert.False(t, restricted.IsRestricted("tenant-2", "tender-9"), "restriction is tenant-scoped")
}

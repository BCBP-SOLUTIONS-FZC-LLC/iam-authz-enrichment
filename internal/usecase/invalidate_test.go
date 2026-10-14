package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

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
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

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
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleMembershipEvent(context.Background(), "tenant-1", usecase.MembershipEventPayload{UserID: "alice"})

	require.Error(t, err)
}

func TestInvalidator_MembershipEvent_EvictNegError_Propagates(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictNegErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleMembershipEvent(context.Background(), "tenant-1", usecase.MembershipEventPayload{UserID: "alice"})

	require.Error(t, err)
}

func TestInvalidator_MembershipRevoked_EvictCtxError_ShortCircuitsBeforeTenderACL(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictCtxErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleMembershipRevoked(context.Background(), "tenant-1", usecase.MembershipEventPayload{UserID: "alice"})

	require.Error(t, err)
	assert.NotContains(t, cache.SortedCalls(), "EvictTenderACLForUser:tenant-1:alice")
}

func TestInvalidator_MembershipRevoked_EvictNegError_Propagates(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictNegErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleMembershipRevoked(context.Background(), "tenant-1", usecase.MembershipEventPayload{UserID: "alice"})

	require.Error(t, err)
}

func TestInvalidator_MembershipRevoked_TenderACLEvictionFails_BestEffortDoesNotPropagate(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictTenderACLErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleMembershipRevoked(context.Background(), "tenant-1", usecase.MembershipEventPayload{UserID: "alice"})

	require.NoError(t, err, "§16 AE-20: the tender-ACL eviction is best-effort — its failure must not fail the whole event")
}

func TestInvalidator_MembershipRevoked_EvictsCtxNegativeAndTenderACL(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleMembershipRevoked(context.Background(), "tenant-1", usecase.MembershipEventPayload{UserID: "alice"})

	require.NoError(t, err)
	assert.Equal(t, []string{
		"EvictMembershipContext:tenant-1:alice",
		"EvictNegative:tenant-1:alice",
		"EvictTenderACLForUser:tenant-1:alice",
	}, cache.SortedCalls())
}

func TestInvalidator_UserUpdated_OtherChange_IsNoOp(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleUserUpdated(context.Background(), "tenant-1", usecase.UserEventPayload{
		UserID: "alice", ChangedFields: []string{"display_name", "job_title", "timezone"},
	})
	require.NoError(t, err)
	assert.Empty(t, cache.SortedCalls(), "a change to a non-eviction field must be a no-op (§5)")
}

func TestInvalidator_UserUpdated_EmailChange_Evicts(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleUserUpdated(context.Background(), "tenant-1", usecase.UserEventPayload{
		UserID: "alice", ChangedFields: []string{"display_name", "email"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"EvictMembershipContext:tenant-1:alice",
		"EvictNegative:tenant-1:alice",
	}, cache.SortedCalls())
}

// TestInvalidator_UserUpdated_StatusChange_Evicts is the regression test for
// the user-disable gap: when a user is disabled, iam-user-profile fires
// UserUpdated with changed_fields=["status"] (alongside UserStatusChanged,
// which user-authz-q does not subscribe to). Without evicting on "status",
// the ae:ctx entry would serve stale Allow decisions for up to 60 s
// (AE_CTX_TTL) after the user is disabled.
func TestInvalidator_UserUpdated_StatusChange_Evicts(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleUserUpdated(context.Background(), "tenant-1", usecase.UserEventPayload{
		UserID: "alice", ChangedFields: []string{"status"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"EvictMembershipContext:tenant-1:alice",
		"EvictNegative:tenant-1:alice",
	}, cache.SortedCalls(), "a status change (user disabled/re-enabled) must evict ae:ctx")
}

func TestInvalidator_UserUpdated_StatusAndEmailChange_Evicts(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleUserUpdated(context.Background(), "tenant-1", usecase.UserEventPayload{
		UserID: "alice", ChangedFields: []string{"status", "email"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"EvictMembershipContext:tenant-1:alice",
		"EvictNegative:tenant-1:alice",
	}, cache.SortedCalls(), "eviction fires once regardless of how many trigger fields are present")
}

func TestInvalidator_UserAvailabilityChanged_Evicts(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

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
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleUserAvailabilityChanged(context.Background(), "tenant-1", usecase.UserEventPayload{UserID: "alice"})

	require.Error(t, err)
}

func TestInvalidator_UserAvailabilityChanged_EvictNegError_Propagates(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictNegErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleUserAvailabilityChanged(context.Background(), "tenant-1", usecase.UserEventPayload{UserID: "alice"})

	require.Error(t, err)
}

func TestInvalidator_UserDeleted_EvictCtxError_ShortCircuitsBeforeTenderACL(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictCtxErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleUserDeleted(context.Background(), "tenant-1", usecase.UserEventPayload{UserID: "alice"})

	require.Error(t, err)
	assert.NotContains(t, cache.SortedCalls(), "EvictTenderACLForUser:tenant-1:alice")
}

func TestInvalidator_UserDeleted_TenderACLEvictionFails_BestEffortDoesNotPropagate(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictTenderACLErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleUserDeleted(context.Background(), "tenant-1", usecase.UserEventPayload{UserID: "alice"})

	require.NoError(t, err, "§5: the tender-ACL eviction is best-effort — its failure must not fail the whole event")
}

func TestInvalidator_UserDeleted_EvictsCtxNegativeAndTenderACL(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

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
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleBillingEvent(context.Background(), "tenant-1")

	require.NoError(t, err)
	assert.Equal(t, []string{"EvictTenantContext:tenant-1"}, cache.SortedCalls(),
		"a tenant-wide billing event must be a single-key eviction, never touching per-user ae:ctx")
}

func TestInvalidator_TenantConverted_EvictsTenantSliceAndRefreshesRealmMap(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	inv := usecase.NewInvalidator(cache, realmMap, usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleTenantConverted(context.Background(), "tenant-1", usecase.TenantRealmEventPayload{Realm: "realm-1"})

	require.NoError(t, err)
	assert.Equal(t, []string{"EvictTenantContext:tenant-1"}, cache.SortedCalls())
	tenant, ok := realmMap.Lookup(context.Background(), "realm-1")
	assert.True(t, ok)
	assert.Equal(t, "tenant-1", tenant)
}

func TestInvalidator_TenantRealmReady_RefreshesRealmMapOnly_NoEviction(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	inv := usecase.NewInvalidator(cache, realmMap, usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	require.NoError(t, inv.HandleTenantRealmReady(context.Background(), "tenant-direct-paid", usecase.TenantRealmEventPayload{Realm: "realm-direct-paid"}))

	assert.Empty(t, cache.SortedCalls(), "§5: TenantRealmReady must NOT evict ae:ctx")
	tenant, ok := realmMap.Lookup(context.Background(), "realm-direct-paid")
	assert.True(t, ok, "the direct-paid-signup case: only TenantRealmReady fires, and it must still update the realm map")
	assert.Equal(t, "tenant-direct-paid", tenant)
}

func TestInvalidator_TenderRestricted_FlipsInMemoryFact_NoEviction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cache := fixtures.NewFakeCache()
	restricted := usecase.NewRestrictedTenderSet(5 * time.Second)
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), restricted, fixtures.NoopLogger{})

	assert.False(t, restricted.IsRestricted(ctx, "tenant-1", "tender-9"))
	require.NoError(t, inv.HandleTenderRestricted(ctx, "tenant-1", usecase.TenderRestrictedPayload{TenderID: "tender-9"}))

	assert.Empty(t, cache.SortedCalls(), "§5: TenderRestricted is not a cache eviction")
	assert.True(t, restricted.IsRestricted(ctx, "tenant-1", "tender-9"))
	assert.False(t, restricted.IsRestricted(ctx, "tenant-2", "tender-9"), "restriction is tenant-scoped")
}

func TestInvalidator_BillingEvent_EvictError_Propagates(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictTenantErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleBillingEvent(context.Background(), "tenant-1")

	require.Error(t, err)
}

func TestInvalidator_TenantLifecycleEvent_EvictsTenantSliceOnly(t *testing.T) {
	t.Parallel()
	for _, eventType := range []string{
		"TenantSuspended", "TenantReactivated", "TenantOffboarded", "TrialExpired", "TrialReactivated",
	} {
		t.Run(eventType, func(t *testing.T) {
			t.Parallel()
			cache := fixtures.NewFakeCache()
			inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

			err := inv.HandleTenantLifecycleEvent(context.Background(), "tenant-1")

			require.NoError(t, err)
			assert.Equal(t, []string{"EvictTenantContext:tenant-1"}, cache.SortedCalls(),
				"%s must be a single ae:tenant eviction — never touching per-user ae:ctx or ae:neg", eventType)
		})
	}
}

func TestInvalidator_TenantLifecycleEvent_EvictError_Propagates(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.EvictTenantErr = errors.New("valkey down")
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleTenantLifecycleEvent(context.Background(), "tenant-1")

	require.Error(t, err)
}

func TestInvalidator_TenantConverted_StoreError(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SetRealmErr = assert.AnError
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	realmMap.BindStore(cache)
	inv := usecase.NewInvalidator(cache, realmMap, usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleTenantConverted(context.Background(), "tenant-1", usecase.TenantRealmEventPayload{Realm: "realm-1"})
	require.Error(t, err)
}

func TestInvalidator_TenantRealmReady_StoreError(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SetRealmErr = assert.AnError
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	realmMap.BindStore(cache)
	inv := usecase.NewInvalidator(cache, realmMap, usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})

	err := inv.HandleTenantRealmReady(context.Background(), "tenant-1", usecase.TenantRealmEventPayload{Realm: "realm-1"})
	require.Error(t, err)
}

func TestInvalidator_TenderRestricted_StoreError(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SetRestrictedErr = assert.AnError
	restricted := usecase.NewRestrictedTenderSet(5 * time.Second)
	restricted.BindStore(cache)
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), restricted, fixtures.NoopLogger{})

	err := inv.HandleTenderRestricted(context.Background(), "tenant-1", usecase.TenderRestrictedPayload{TenderID: "tender-9"})
	require.Error(t, err)
}

func TestNewInvalidator_WithRecorder_UsesIt(t *testing.T) {
	t.Parallel()
	// Exercises the len(recorder)>0 && recorder[0]!=nil branch in NewInvalidator.
	cache := fixtures.NewFakeCache()
	cache.EvictTenderACLErr = errors.New("scan failed")
	rec := usecase.NoopRecorder{}
	inv := usecase.NewInvalidator(
		cache,
		usecase.NewRealmMap(nil, 5*time.Second),
		usecase.NewRestrictedTenderSet(5*time.Second),
		fixtures.NoopLogger{},
		rec, // explicit non-nil recorder — exercises the assignment branch
	)

	// HandleUserDeleted triggers EvictTenderACLForUser; the error is best-effort
	// (log + ObserveEvictionError) and never returned, so Handle succeeds.
	err := inv.HandleUserDeleted(context.Background(), "tenant-1", usecase.UserEventPayload{UserID: "alice"})
	require.NoError(t, err)
}

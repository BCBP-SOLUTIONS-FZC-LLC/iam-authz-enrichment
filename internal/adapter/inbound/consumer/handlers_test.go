package consumer

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/test/fixtures"
)

func testDeps(cache *fixtures.FakeCache) Deps {
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})
	return Deps{Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv}
}

func envelope(t *testing.T, eventType, tenantID string, payload any) events.Envelope[json.RawMessage] {
	t.Helper()
	b, err := json.Marshal(payload)
	require.NoError(t, err)
	return events.Envelope[json.RawMessage]{ID: "evt-1", Type: eventType, TenantID: tenantID, Payload: json.RawMessage(b)}
}

func TestMembershipHandler_KnownType_Evicts(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	deps := testDeps(cache)
	handler := membershipHandler(deps)

	err := handler(context.Background(), envelope(t, "DepartmentMembershipGranted", "tenant-1", map[string]string{"user_id": "alice"}))

	require.NoError(t, err)
	assert.Contains(t, cache.SortedCalls(), "EvictMembershipContext:tenant-1:alice")
}

func badPayloadEnvelope(eventType string) events.Envelope[json.RawMessage] {
	return events.Envelope[json.RawMessage]{ID: "evt-1", Type: eventType, TenantID: "tenant-1", Payload: json.RawMessage(`"not-an-object"`)}
}

func TestMembershipHandler_DecodeError(t *testing.T) {
	t.Parallel()
	handler := membershipHandler(testDeps(fixtures.NewFakeCache()))

	err := handler(context.Background(), badPayloadEnvelope("DepartmentMembershipGranted"))

	assert.Error(t, err)
}

func TestMembershipHandler_UnknownType_NoOp(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	handler := membershipHandler(testDeps(cache))

	err := handler(context.Background(), envelope(t, "SomeUnrelatedEvent", "tenant-1", map[string]string{"user_id": "alice"}))

	require.NoError(t, err)
	assert.Empty(t, cache.SortedCalls())
}

func TestUserHandler_UserUpdated_EmailFilter(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	handler := userHandler(testDeps(cache))

	err := handler(context.Background(), envelope(t, "UserUpdated", "tenant-1", map[string]any{
		"user_id": "alice", "changed_fields": []string{"display_name"},
	}))
	require.NoError(t, err)
	assert.Empty(t, cache.SortedCalls(), "non-email UserUpdated must be a no-op")

	err = handler(context.Background(), envelope(t, "UserUpdated", "tenant-1", map[string]any{
		"user_id": "alice", "changed_fields": []string{"email"},
	}))
	require.NoError(t, err)
	assert.Contains(t, cache.SortedCalls(), "EvictMembershipContext:tenant-1:alice")
}

func TestUserHandler_DecodeError(t *testing.T) {
	t.Parallel()
	handler := userHandler(testDeps(fixtures.NewFakeCache()))

	err := handler(context.Background(), badPayloadEnvelope("UserUpdated"))

	assert.Error(t, err)
}

func TestUserHandler_UnknownType_NoOp(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	handler := userHandler(testDeps(cache))

	err := handler(context.Background(), envelope(t, "SomeUnrelatedEvent", "tenant-1", map[string]string{"user_id": "alice"}))

	require.NoError(t, err)
	assert.Empty(t, cache.SortedCalls())
}

func TestUserHandler_UserAvailabilityChanged_Evicts(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	handler := userHandler(testDeps(cache))

	err := handler(context.Background(), envelope(t, "UserAvailabilityChanged", "tenant-1", map[string]string{"user_id": "alice"}))

	require.NoError(t, err)
	assert.Contains(t, cache.SortedCalls(), "EvictMembershipContext:tenant-1:alice")
}

func TestUserHandler_UserDeleted_EvictsTenderACL(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	handler := userHandler(testDeps(cache))

	err := handler(context.Background(), envelope(t, "UserDeleted", "tenant-1", map[string]string{"user_id": "alice"}))

	require.NoError(t, err)
	assert.Contains(t, cache.SortedCalls(), "EvictTenderACLForUser:tenant-1:alice")
}

func TestBillingHandler_KnownTypes_EvictTenant(t *testing.T) {
	t.Parallel()
	for _, eventType := range []string{"TenantPlanChanged", "TenantSubscriptionCancelled", "TenantReactivated"} {
		cache := fixtures.NewFakeCache()
		handler := billingHandler(testDeps(cache))

		err := handler(context.Background(), envelope(t, eventType, "tenant-1", map[string]string{}))

		require.NoError(t, err)
		assert.Equal(t, []string{"EvictTenantContext:tenant-1"}, cache.SortedCalls(), eventType)
	}
}

func TestBillingHandler_UnknownType_NoOp(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	handler := billingHandler(testDeps(cache))

	err := handler(context.Background(), envelope(t, "SomeUnrelatedEvent", "tenant-1", map[string]string{}))

	require.NoError(t, err)
	assert.Empty(t, cache.SortedCalls())
}

func TestTenantHandler_DecodeError(t *testing.T) {
	t.Parallel()
	handler := tenantHandler(testDeps(fixtures.NewFakeCache()))

	err := handler(context.Background(), badPayloadEnvelope("TenantConverted"))

	assert.Error(t, err)
}

func TestTenantHandler_UnknownType_NoOp(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	realmMap := usecase.NewRealmMap(nil)
	inv := usecase.NewInvalidator(cache, realmMap, usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})
	handler := tenantHandler(Deps{Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv})

	err := handler(context.Background(), envelope(t, "SomeUnrelatedEvent", "tenant-1", map[string]string{"realm": "realm-1"}))

	require.NoError(t, err)
	assert.Empty(t, cache.SortedCalls())
	_, ok := realmMap.Lookup("realm-1")
	assert.False(t, ok)
}

func TestTenantHandler_TenantConverted_EvictsAndRefreshesRealmMap(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	realmMap := usecase.NewRealmMap(nil)
	inv := usecase.NewInvalidator(cache, realmMap, usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})
	deps := Deps{Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv}
	handler := tenantHandler(deps)

	err := handler(context.Background(), envelope(t, "TenantConverted", "tenant-1", map[string]string{"realm": "realm-1"}))

	require.NoError(t, err)
	assert.Equal(t, []string{"EvictTenantContext:tenant-1"}, cache.SortedCalls())
	tenant, ok := realmMap.Lookup("realm-1")
	assert.True(t, ok)
	assert.Equal(t, "tenant-1", tenant)
}

func TestTenantHandler_TenantRealmReady_NoEviction(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	realmMap := usecase.NewRealmMap(nil)
	inv := usecase.NewInvalidator(cache, realmMap, usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})
	deps := Deps{Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv}
	handler := tenantHandler(deps)

	err := handler(context.Background(), envelope(t, "TenantRealmReady", "tenant-direct-paid", map[string]string{"realm": "realm-direct-paid"}))

	require.NoError(t, err)
	assert.Empty(t, cache.SortedCalls())
	tenant, ok := realmMap.Lookup("realm-direct-paid")
	assert.True(t, ok)
	assert.Equal(t, "tenant-direct-paid", tenant)
}

func TestTenderHandler_TenderRestricted_FlipsFact(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	restricted := usecase.NewRestrictedTenderSet()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), restricted, fixtures.NoopLogger{})
	deps := Deps{Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv}
	handler := tenderHandler(deps)

	err := handler(context.Background(), envelope(t, "TenderRestricted", "tenant-1", map[string]string{"tender_id": "tender-9"}))

	require.NoError(t, err)
	assert.Empty(t, cache.SortedCalls())
	assert.True(t, restricted.IsRestricted("tenant-1", "tender-9"))
}

func TestTenderHandler_UnknownType_NoOp(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	restricted := usecase.NewRestrictedTenderSet()
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), restricted, fixtures.NoopLogger{})
	handler := tenderHandler(Deps{Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv})

	err := handler(context.Background(), envelope(t, "SomeUnrelatedEvent", "tenant-1", map[string]string{"tender_id": "tender-9"}))

	require.NoError(t, err)
	assert.False(t, restricted.IsRestricted("tenant-1", "tender-9"))
}

func TestTenderHandler_DecodeError(t *testing.T) {
	t.Parallel()
	handler := tenderHandler(testDeps(fixtures.NewFakeCache()))

	err := handler(context.Background(), badPayloadEnvelope("TenderRestricted"))

	assert.Error(t, err)
}

func TestDedupingHandler_RetriesAfterHandlerFailure(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	var calls int
	inner := func(context.Context, events.Envelope[json.RawMessage]) error {
		calls++
		if calls == 1 {
			return assert.AnError
		}
		return nil
	}
	deps := Deps{Cache: cache, Log: fixtures.NoopLogger{}}
	wrapped := dedupingHandler(deps, inner)

	env := envelope(t, "AnyType", "tenant-1", map[string]string{})
	err := wrapped(context.Background(), env)
	require.Error(t, err, "a failed handler must propagate its error so SQS redelivers")

	err = wrapped(context.Background(), env)
	require.NoError(t, err, "the redelivery must be a real retry, not a false-positive dedup skip")
	assert.Equal(t, 2, calls, "a message that failed must not be silently swallowed on retry — it must reach the DLQ after enough failures, not get falsely acked")
}

func TestDedupingHandler_SkipsAlreadyProcessedEvent(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	var calls int
	inner := func(context.Context, events.Envelope[json.RawMessage]) error {
		calls++
		return nil
	}
	deps := Deps{Cache: cache, Log: fixtures.NoopLogger{}}
	wrapped := dedupingHandler(deps, inner)

	env := envelope(t, "AnyType", "tenant-1", map[string]string{})
	require.NoError(t, wrapped(context.Background(), env))
	require.NoError(t, wrapped(context.Background(), env))

	assert.Equal(t, 1, calls, "a redelivered event ID must not be processed twice")
}

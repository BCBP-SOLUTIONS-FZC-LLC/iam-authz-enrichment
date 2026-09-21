package usecase_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/test/fixtures"
)

func TestResolveTenant_DedicatedRealm(t *testing.T) {
	t.Parallel()
	realmMap := usecase.NewRealmMap(map[string]string{
		"https://kc.example.com/realms/acme": "tenant-acme",
	}, 5*time.Second)

	tenant, ok := usecase.ResolveTenant(context.Background(), usecase.Claims{
		Issuer: "https://kc.example.com/realms/acme",
	}, realmMap, "https://kc.example.com/realms/shared-trial")

	assert.True(t, ok)
	assert.Equal(t, "tenant-acme", tenant)
}

func TestResolveTenant_SharedRealmFallsBackToClaim(t *testing.T) {
	t.Parallel()
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	shared := "https://kc.example.com/realms/shared-trial"

	tenant, ok := usecase.ResolveTenant(context.Background(), usecase.Claims{
		Issuer:   shared,
		TenantID: "tenant-trial-42",
	}, realmMap, shared)

	assert.True(t, ok)
	assert.Equal(t, "tenant-trial-42", tenant)
}

func TestResolveTenant_SharedRealmWithoutTenantClaim_MalformedIdentity(t *testing.T) {
	t.Parallel()
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	shared := "https://kc.example.com/realms/shared-trial"

	_, ok := usecase.ResolveTenant(context.Background(), usecase.Claims{Issuer: shared, TenantID: ""}, realmMap, shared)

	assert.False(t, ok)
}

func TestResolveTenant_UnknownIssuer_MalformedIdentity(t *testing.T) {
	t.Parallel()
	realmMap := usecase.NewRealmMap(map[string]string{
		"https://kc.example.com/realms/acme": "tenant-acme",
	}, 5*time.Second)

	_, ok := usecase.ResolveTenant(context.Background(), usecase.Claims{
		Issuer:   "https://kc.example.com/realms/some-other-unknown-realm",
		TenantID: "tenant-doesnt-matter",
	}, realmMap, "https://kc.example.com/realms/shared-trial")

	assert.False(t, ok, "iss matching neither a known dedicated realm nor the shared realm must not resolve")
}

func TestResolveTenant_EmptyIssuer_MalformedIdentity(t *testing.T) {
	t.Parallel()
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	_, ok := usecase.ResolveTenant(context.Background(), usecase.Claims{Issuer: ""}, realmMap, "")
	assert.False(t, ok)
}

// TC-055: RealmMap concurrent reads and writes — no data race.
// Run with: go test -race ./internal/usecase/...
func TestRealmMap_ConcurrentReadsAndWrites_NoRace(t *testing.T) {
	rm := usecase.NewRealmMap(nil, 5*time.Second)
	var wg sync.WaitGroup

	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = rm.Set(context.Background(), fmt.Sprintf("realm-%d", i), fmt.Sprintf("tenant-%d", i))
		}(i)
	}
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rm.Lookup(context.Background(), fmt.Sprintf("realm-%d", i%10))
		}(i)
	}
	wg.Wait()
}

// TC-056: RestrictedTenderSet concurrent MarkRestricted + IsRestricted — no
// data race. A race here means a restricted tender could be treated as open,
// bypassing the tender-ACL overlay for all authenticated users.
// Run with: go test -race ./internal/usecase/...
func TestRestrictedTenderSet_ConcurrentMarkAndCheck_NoRace(t *testing.T) {
	s := usecase.NewRestrictedTenderSet(5 * time.Second)
	var wg sync.WaitGroup

	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = s.MarkRestricted(context.Background(), "tenant-1", fmt.Sprintf("tender-%d", i))
		}(i)
	}
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.IsRestricted(context.Background(), "tenant-1", fmt.Sprintf("tender-%d", i%10))
		}(i)
	}
	wg.Wait()
}

func TestRealmMap_SetThenLookup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	_, ok := realmMap.Lookup(ctx, "realm-x")
	assert.False(t, ok)

	require.NoError(t, realmMap.Set(ctx, "realm-x", "tenant-x"))
	tenant, ok := realmMap.Lookup(ctx, "realm-x")
	assert.True(t, ok)
	assert.Equal(t, "tenant-x", tenant)
}

func TestRealmMap_StoreVisibleToOtherReplica(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := fixtures.NewFakeCache()
	writer := usecase.NewRealmMap(nil, 5*time.Second)
	writer.BindStore(store)
	reader := usecase.NewRealmMap(nil, 5*time.Second)
	reader.BindStore(store)

	require.NoError(t, writer.Set(ctx, "realm-x", "tenant-x"))
	tenant, ok := reader.Lookup(ctx, "realm-x")
	assert.True(t, ok)
	assert.Equal(t, "tenant-x", tenant)
}

func TestRealmMap_StoreErrorOnSet_DoesNotWriteLocal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := fixtures.NewFakeCache()
	store.SetRealmErr = assert.AnError
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	realmMap.BindStore(store)

	err := realmMap.Set(ctx, "realm-x", "tenant-x")
	require.Error(t, err)
	_, ok := realmMap.Lookup(ctx, "realm-x")
	assert.False(t, ok)
}

func TestRealmMap_StoreErrorOnGet_TreatedAsMiss(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := fixtures.NewFakeCache()
	store.RealmErr = assert.AnError
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	realmMap.BindStore(store)

	_, ok := realmMap.Lookup(ctx, "realm-x")
	assert.False(t, ok)
}

func TestRealmMap_StoreErrorOnGet_NotCached_RetriesNextCall(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := fixtures.NewFakeCache()
	store.RealmErr = assert.AnError
	// A long negTTL: if the error were wrongly cached as a confirmed
	// negative, the second Lookup below would be served from L1 instead
	// of retrying the store.
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	realmMap.BindStore(store)

	_, ok := realmMap.Lookup(ctx, "realm-x")
	assert.False(t, ok)
	_, ok = realmMap.Lookup(ctx, "realm-x")
	assert.False(t, ok)

	assert.Equal(t, []string{"GetRealm:realm-x", "GetRealm:realm-x"}, store.SortedCalls(),
		"a transient store error must not be cached as a confirmed negative — every call must retry the store, not wait out negTTL")
}

func TestRealmMap_PersistSeed_WritesStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := fixtures.NewFakeCache()
	realmMap := usecase.NewRealmMap(map[string]string{"realm-a": "tenant-a"}, 5*time.Second)
	realmMap.BindStore(store)
	require.NoError(t, realmMap.PersistSeed(ctx))
	assert.Contains(t, store.SortedCalls(), "SetRealm:realm-a")
}

func TestRealmMap_PersistSeed_NoStore_NoOp(t *testing.T) {
	t.Parallel()
	require.NoError(t, usecase.NewRealmMap(map[string]string{"a": "b"}, 5*time.Second).PersistSeed(context.Background()))
}

func TestRealmMap_PersistSeed_StoreError(t *testing.T) {
	t.Parallel()
	store := fixtures.NewFakeCache()
	store.SetRealmErr = assert.AnError
	realmMap := usecase.NewRealmMap(map[string]string{"realm-a": "tenant-a"}, 5*time.Second)
	realmMap.BindStore(store)
	require.Error(t, realmMap.PersistSeed(context.Background()))
}

func TestRealmMap_PersistSeed_OneFailure_StillAttemptsEveryEntry(t *testing.T) {
	t.Parallel()
	store := fixtures.NewFakeCache()
	store.SetRealmErr = assert.AnError
	realmMap := usecase.NewRealmMap(map[string]string{
		"realm-a": "tenant-a", "realm-b": "tenant-b", "realm-c": "tenant-c",
	}, 5*time.Second)
	realmMap.BindStore(store)

	err := realmMap.PersistSeed(context.Background())

	require.Error(t, err)
	assert.Equal(t, []string{"SetRealm:realm-a", "SetRealm:realm-b", "SetRealm:realm-c"}, store.SortedCalls(),
		"every seed entry must be attempted even after an earlier one fails, since map iteration order is randomized")
}

func TestResolveTenant_DedicatedRealmFromStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := fixtures.NewFakeCache()
	require.NoError(t, store.SetRealm(ctx, "https://kc.example.com/realms/acme", "tenant-acme"))
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	realmMap.BindStore(store)

	tenant, ok := usecase.ResolveTenant(ctx, usecase.Claims{
		Issuer: "https://kc.example.com/realms/acme",
	}, realmMap, "https://kc.example.com/realms/shared-trial")

	assert.True(t, ok)
	assert.Equal(t, "tenant-acme", tenant)
}

func TestResolveTenant_StoreBoundButRealmNotFound_MalformedIdentity(t *testing.T) {
	t.Parallel()
	store := fixtures.NewFakeCache()
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	realmMap.BindStore(store)

	_, ok := usecase.ResolveTenant(context.Background(), usecase.Claims{
		Issuer: "https://kc.example.com/realms/never-seen",
	}, realmMap, "https://kc.example.com/realms/shared-trial")

	assert.False(t, ok, "a store bound but with no matching realm entry must still deny, not panic or false-positive")
}

func TestResolveTenant_NegativeCache_AvoidsRepeatedStoreLookups_ThenRevalidatesAfterTTL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := fixtures.NewFakeCache()
	realmMap := usecase.NewRealmMap(nil, 20*time.Millisecond)
	realmMap.BindStore(store)
	claims := usecase.Claims{Issuer: "https://kc.example.com/realms/never-seen"}

	_, ok := usecase.ResolveTenant(ctx, claims, realmMap, "")
	assert.False(t, ok, "first call misses L1, queries the store, caches a negative")

	_, ok = usecase.ResolveTenant(ctx, claims, realmMap, "")
	assert.False(t, ok, "still within negTTL — must be served from L1 without another store round-trip")
	assert.Equal(t, []string{"GetRealm:https://kc.example.com/realms/never-seen"}, store.SortedCalls(),
		"a second ResolveTenant call for the same unresolvable issuer within negTTL must not hit the store again")

	require.NoError(t, store.SetRealm(ctx, claims.Issuer, "tenant-arrived-late"))
	time.Sleep(30 * time.Millisecond)

	tenant, ok := usecase.ResolveTenant(ctx, claims, realmMap, "")
	assert.True(t, ok, "negTTL elapsed — re-checks the store and observes another replica's Set")
	assert.Equal(t, "tenant-arrived-late", tenant)
}

// blockingGetRealmCache lets a test pause ResolveTenant mid-flight, inside
// its store.GetRealm call, to deterministically land a concurrent Set
// before the stale GetRealm result returns.
type blockingGetRealmCache struct {
	*fixtures.FakeCache
	started chan struct{}
	resume  chan struct{}
}

func (c *blockingGetRealmCache) GetRealm(context.Context, string) (string, bool, error) {
	close(c.started)
	<-c.resume
	return "", false, nil // stale: the store hadn't observed the concurrent Set yet
}

func TestRealmMap_ConcurrentSetDuringStaleLookup_DoesNotClobber(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cache := &blockingGetRealmCache{
		FakeCache: fixtures.NewFakeCache(),
		started:   make(chan struct{}),
		resume:    make(chan struct{}),
	}
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	realmMap.BindStore(cache)

	result := make(chan string, 1)
	ok := make(chan bool, 1)
	go func() {
		tenant, found := usecase.ResolveTenant(ctx, usecase.Claims{Issuer: "realm-x"}, realmMap, "")
		result <- tenant
		ok <- found
	}()

	<-cache.started
	require.NoError(t, realmMap.Set(ctx, "realm-x", "tenant-x"))
	close(cache.resume)

	assert.True(t, <-ok, "a Set landing while a stale GetRealm is in flight must win, not be clobbered by the stale negative")
	assert.Equal(t, "tenant-x", <-result)
	tenant, found := realmMap.Lookup(ctx, "realm-x")
	assert.True(t, found, "the positive entry must stick after the race")
	assert.Equal(t, "tenant-x", tenant)
}

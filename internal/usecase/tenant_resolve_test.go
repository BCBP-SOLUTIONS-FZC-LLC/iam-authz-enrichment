package usecase_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
)

func TestResolveTenant_DedicatedRealm(t *testing.T) {
	t.Parallel()
	realmMap := usecase.NewRealmMap(map[string]string{
		"https://kc.example.com/realms/acme": "tenant-acme",
	})

	tenant, ok := usecase.ResolveTenant(usecase.Claims{
		Issuer: "https://kc.example.com/realms/acme",
	}, realmMap, "https://kc.example.com/realms/shared-trial")

	assert.True(t, ok)
	assert.Equal(t, "tenant-acme", tenant)
}

func TestResolveTenant_SharedRealmFallsBackToClaim(t *testing.T) {
	t.Parallel()
	realmMap := usecase.NewRealmMap(nil)
	shared := "https://kc.example.com/realms/shared-trial"

	tenant, ok := usecase.ResolveTenant(usecase.Claims{
		Issuer:   shared,
		TenantID: "tenant-trial-42",
	}, realmMap, shared)

	assert.True(t, ok)
	assert.Equal(t, "tenant-trial-42", tenant)
}

func TestResolveTenant_SharedRealmWithoutTenantClaim_MalformedIdentity(t *testing.T) {
	t.Parallel()
	realmMap := usecase.NewRealmMap(nil)
	shared := "https://kc.example.com/realms/shared-trial"

	_, ok := usecase.ResolveTenant(usecase.Claims{Issuer: shared, TenantID: ""}, realmMap, shared)

	assert.False(t, ok)
}

func TestResolveTenant_UnknownIssuer_MalformedIdentity(t *testing.T) {
	t.Parallel()
	realmMap := usecase.NewRealmMap(map[string]string{
		"https://kc.example.com/realms/acme": "tenant-acme",
	})

	_, ok := usecase.ResolveTenant(usecase.Claims{
		Issuer:   "https://kc.example.com/realms/some-other-unknown-realm",
		TenantID: "tenant-doesnt-matter",
	}, realmMap, "https://kc.example.com/realms/shared-trial")

	assert.False(t, ok, "iss matching neither a known dedicated realm nor the shared realm must not resolve")
}

func TestResolveTenant_EmptyIssuer_MalformedIdentity(t *testing.T) {
	t.Parallel()
	realmMap := usecase.NewRealmMap(nil)
	_, ok := usecase.ResolveTenant(usecase.Claims{Issuer: ""}, realmMap, "")
	assert.False(t, ok)
}

// TC-055: RealmMap concurrent reads and writes — no data race.
// Run with: go test -race ./internal/usecase/...
func TestRealmMap_ConcurrentReadsAndWrites_NoRace(t *testing.T) {
	rm := usecase.NewRealmMap(nil)
	var wg sync.WaitGroup

	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rm.Set(fmt.Sprintf("realm-%d", i), fmt.Sprintf("tenant-%d", i))
		}(i)
	}
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rm.Lookup(fmt.Sprintf("realm-%d", i%10))
		}(i)
	}
	wg.Wait()
}

// TC-056: RestrictedTenderSet concurrent MarkRestricted + IsRestricted — no
// data race. A race here means a restricted tender could be treated as open,
// bypassing the tender-ACL overlay for all authenticated users.
// Run with: go test -race ./internal/usecase/...
func TestRestrictedTenderSet_ConcurrentMarkAndCheck_NoRace(t *testing.T) {
	s := usecase.NewRestrictedTenderSet()
	var wg sync.WaitGroup

	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.MarkRestricted("tenant-1", fmt.Sprintf("tender-%d", i))
		}(i)
	}
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.IsRestricted("tenant-1", fmt.Sprintf("tender-%d", i%10))
		}(i)
	}
	wg.Wait()
}

func TestRealmMap_SetThenLookup(t *testing.T) {
	t.Parallel()
	realmMap := usecase.NewRealmMap(nil)
	_, ok := realmMap.Lookup("realm-x")
	assert.False(t, ok)

	realmMap.Set("realm-x", "tenant-x")
	tenant, ok := realmMap.Lookup("realm-x")
	assert.True(t, ok)
	assert.Equal(t, "tenant-x", tenant)
}

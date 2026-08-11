package usecase_test

import (
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

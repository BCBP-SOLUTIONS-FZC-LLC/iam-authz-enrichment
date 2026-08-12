package domain_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// TestMFAFreshnessSecondsNeverCached is the §4.4/§8.3 regression test: this
// service must never write mfa_freshness_seconds into any cache key it
// owns. It fails if a future change starts putting this field into any
// struct that ae:ctx or ae:tenant cache — the single most important rule in
// §4 (get it wrong and you reintroduce a real security bug: a tenant
// tightening its MFA window wouldn't take effect for up to 60s instead of
// immediately).
//
// This asserts the invariant two ways: (1) reflection over every field/json
// tag of the two structs the valkey adapter caches, and (2) that the actual
// JSON produced by marshaling a populated instance never contains the
// substring anywhere — belt and suspenders against a future field with a
// different Go name but the same json tag, or vice versa.
func TestMFAFreshnessSecondsNeverCached(t *testing.T) {
	t.Parallel()

	assertNoMFAField(t, domain.MembershipContext{})
	assertNoMFAField(t, domain.TenantContext{})

	membership := domain.MembershipContext{
		Roles:       []string{"tenant_admin"},
		Departments: []domain.Department{{DepartmentID: "d1", Level: "approver"}},
		Delegations: []domain.Delegation{{FromUserID: "u2", DepartmentID: "d1", Level: "approver"}},
	}
	b, err := json.Marshal(membership)
	require.NoError(t, err)
	assert.NotContains(t, strings.ToLower(string(b)), "mfa_freshness_seconds")
	assert.NotContains(t, strings.ToLower(string(b)), "mfafreshness")

	tenant := domain.TenantContext{Plan: "pro", FeatureFlags: []string{"x"}, SubscriptionStatus: "active", ReadOnly: false}
	b, err = json.Marshal(tenant)
	require.NoError(t, err)
	assert.NotContains(t, strings.ToLower(string(b)), "mfa_freshness_seconds")
	assert.NotContains(t, strings.ToLower(string(b)), "mfafreshness")
}

func assertNoMFAField(t *testing.T, v any) {
	t.Helper()
	typ := reflect.TypeOf(v)
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		lowerName := strings.ToLower(f.Name)
		lowerTag := strings.ToLower(f.Tag.Get("json"))
		assert.NotContains(t, lowerName, "mfafreshness", "field %s.%s must never carry mfa_freshness_seconds", typ.Name(), f.Name)
		assert.NotContains(t, lowerTag, "mfa_freshness_seconds", "field %s.%s's json tag must never be mfa_freshness_seconds", typ.Name(), f.Name)
	}
}

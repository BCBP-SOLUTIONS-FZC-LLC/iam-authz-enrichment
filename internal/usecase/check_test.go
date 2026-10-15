package usecase_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain/policy"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/test/fixtures"
)

const (
	sharedRealmIssuer = "https://kc.example.com/realms/shared-trial"
	dedicatedIssuer   = "https://kc.example.com/realms/acme"
	tenant            = "tenant-acme"
	user              = "alice"
)

func newTestChecker(cache usecase.Cache, org usecase.OrgMembershipClient, restricted *usecase.RestrictedTenderSet) *usecase.Checker {
	realmMap := usecase.NewRealmMap(map[string]string{dedicatedIssuer: tenant}, 5*time.Second)
	if restricted == nil {
		restricted = usecase.NewRestrictedTenderSet(5 * time.Second)
	}
	return usecase.NewChecker(cache, org, realmMap, restricted, fixtures.NoopLogger{}, usecase.NoopRecorder{}, usecase.CheckerConfig{
		SharedRealmIssuer: sharedRealmIssuer,
	})
}

func baseClaims() usecase.Claims {
	return usecase.Claims{Subject: user, Issuer: dedicatedIssuer}
}

func TestCheck_MalformedIdentity_UnknownIssuer_ShortCircuits(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	org := &fixtures.FakeOrgMembershipClient{}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: usecase.Claims{Subject: user, Issuer: "https://kc.example.com/realms/unknown"},
	})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyMalformedIdentity, decision.Reason)
	assert.Zero(t, org.MembershipCalls, "malformed identity must short-circuit before any sibling call")
}

func TestCheck_SubjectResolution_404_SetNegativeFails_StillDenies(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SetNegErr = errors.New("valkey down")
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, error) {
			return domain.MembershipContext{}, domain.TenantContext{}, domain.ErrNotFound
		},
	}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims()})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyUnresolvableSubject, decision.Reason, "a best-effort SetNegative failure must not change the deny reason")
}

func TestCheck_SubjectResolution_404_DeniesAndNegativeCaches(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, error) {
			return domain.MembershipContext{}, domain.TenantContext{}, domain.ErrNotFound
		},
	}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims()})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyUnresolvableSubject, decision.Reason)
	assert.Contains(t, cache.SortedCalls(), "SetNegative:"+tenant+":"+user)
}

func TestCheck_NegativeCacheHit_ShortCircuits_NoSiblingCall(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedNegative(tenant, user)
	org := &fixtures.FakeOrgMembershipClient{}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims()})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyUnresolvableSubject, decision.Reason)
	assert.Zero(t, org.MembershipCalls, "§4.3: a negative-cache hit must collapse the repeat rebuild call")
}

func TestCheck_FreshCacheHit_Allows_NoSiblingCall(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.MembershipContext{
		Roles:       []string{"tenant_admin"},
		Departments: []domain.Department{{DepartmentID: "eng", Level: "reviewer"}},
	}, domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.TenantContext{Plan: "pro", FeatureFlags: []string{"flag-a"}}, domain.CacheFresh)
	org := &fixtures.FakeOrgMembershipClient{}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "GET"},
	})

	require.True(t, decision.Allow)
	assert.Zero(t, org.MembershipCalls, "a fresh cache hit must never call the sibling")
	assert.Equal(t, tenant, decision.Headers[domain.HeaderTenantID])
	assert.Equal(t, user, decision.Headers[domain.HeaderUserID])
	assert.Equal(t, "tenant_admin", decision.Headers[domain.HeaderTenantRoles])
	assert.Equal(t, "eng:reviewer", decision.Headers[domain.HeaderDepartments])
	assert.Equal(t, "pro", decision.Headers[domain.HeaderPlan])
	assert.Equal(t, "flag-a", decision.Headers[domain.HeaderFeatureFlags])
}

func TestCheck_ReadOnlyGate_DeniesMutation_AllowsRead(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.TenantContext{ReadOnly: true, FeatureFlags: []string{}}, domain.CacheFresh)
	checker := newTestChecker(cache, &fixtures.FakeOrgMembershipClient{}, nil)

	mutation := checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims(), Request: policy.RequestFacts{Method: "POST"}})
	assert.False(t, mutation.Allow)
	assert.Equal(t, domain.DenyTenantReadOnly, mutation.Reason)

	read := checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims(), Request: policy.RequestFacts{Method: "GET"}})
	assert.True(t, read.Allow, "read methods are never affected by the read-only gate")
}

func TestCheck_BaseRoleInsufficient(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	checker := newTestChecker(cache, &fixtures.FakeOrgMembershipClient{}, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "POST", Action: policy.ActionManageDepartmentMemberships},
	})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyRoleInsufficient, decision.Reason)
}

// Precedence-order tests (§3.1/§12): a request that would independently fail
// multiple checks must return the reason the precedence order predicts.

func TestCheck_Precedence_ReadOnlyWinsOverRoleInsufficient(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	// No roles at all (would fail the base policy, step 3) AND read-only
	// (would fail step 2). Step 2 must win.
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.TenantContext{ReadOnly: true, FeatureFlags: []string{}}, domain.CacheFresh)
	checker := newTestChecker(cache, &fixtures.FakeOrgMembershipClient{}, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "POST", Action: policy.ActionManageDepartmentMemberships},
	})

	assert.Equal(t, domain.DenyTenantReadOnly, decision.Reason)
}

func TestCheck_Precedence_RoleInsufficientWinsOverTenderACL(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	restricted := usecase.NewRestrictedTenderSet(5 * time.Second)
	require.NoError(t, restricted.MarkRestricted(context.Background(), tenant, "tender-1"))
	org := &fixtures.FakeOrgMembershipClient{
		GetTenderACLFunc: func(ctx context.Context, tenant, tenderID, user string) (domain.TenderACL, error) {
			return domain.TenderACL{}, nil // no grant -> would deny at step 4 too
		},
	}
	checker := newTestChecker(cache, org, restricted)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: baseClaims(),
		Request: policy.RequestFacts{
			Method: "POST", Action: policy.ActionManageDepartmentMemberships, // no roles -> fails step 3
			TenderID: "tender-1", RequiredAccessLevel: domain.AccessLevelView,
		},
	})

	assert.Equal(t, domain.DenyRoleInsufficient, decision.Reason)
	assert.Zero(t, org.TenderACLCalls, "step 4 must only run if step 3 would otherwise allow")
}

func TestCheck_Precedence_TenderACLWinsOverMFA(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	restricted := usecase.NewRestrictedTenderSet(5 * time.Second)
	require.NoError(t, restricted.MarkRestricted(context.Background(), tenant, "tender-1"))
	org := &fixtures.FakeOrgMembershipClient{
		GetTenderACLFunc: func(ctx context.Context, tenant, tenderID, user string) (domain.TenderACL, error) {
			return domain.TenderACL{}, nil // insufficient -> denies at step 4
		},
	}
	checker := newTestChecker(cache, org, restricted)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: usecase.Claims{Subject: user, Issuer: dedicatedIssuer, AuthTime: 0}, // ancient auth_time -> would fail MFA gate too
		Request: policy.RequestFacts{
			Method: "POST", Action: policy.ActionGeneric,
			TenderID: "tender-1", RequiredAccessLevel: domain.AccessLevelView,
			RequiredDepartmentLevel: policy.LevelApprover,
		},
	})

	assert.Equal(t, domain.DenyTenderACLInsufficient, decision.Reason)
	assert.Zero(t, org.MFACalls, "step 5 must only run if steps 1-4 would otherwise allow")
}

func TestCheck_TenderACL_CacheHit_SkipsSiblingCall(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	require.NoError(t, cache.SetTenderACL(context.Background(), tenant, "tender-1", user, domain.TenderACL{HasAccess: true, AccessLevel: domain.AccessLevelApprove}))
	restricted := usecase.NewRestrictedTenderSet(5 * time.Second)
	require.NoError(t, restricted.MarkRestricted(context.Background(), tenant, "tender-1"))
	org := &fixtures.FakeOrgMembershipClient{}
	checker := newTestChecker(cache, org, restricted)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "GET", TenderID: "tender-1", RequiredAccessLevel: domain.AccessLevelView},
	})

	assert.True(t, decision.Allow)
	assert.Zero(t, org.TenderACLCalls, "a cache hit must never call the sibling")
}

func TestCheck_TenderACL_SetCacheFails_StillAllowsOnGrant(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	cache.SetTenderACLErr = errors.New("valkey down")
	restricted := usecase.NewRestrictedTenderSet(5 * time.Second)
	require.NoError(t, restricted.MarkRestricted(context.Background(), tenant, "tender-1"))
	org := &fixtures.FakeOrgMembershipClient{
		GetTenderACLFunc: func(ctx context.Context, tenant, tenderID, user string) (domain.TenderACL, error) {
			return domain.TenderACL{HasAccess: true, AccessLevel: domain.AccessLevelApprove}, nil
		},
	}
	checker := newTestChecker(cache, org, restricted)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "GET", TenderID: "tender-1", RequiredAccessLevel: domain.AccessLevelView},
	})

	assert.True(t, decision.Allow, "a best-effort cache write failure must not affect the decision")
}

func TestCheck_TenderACL_GetCacheErrors_FallsThroughToSibling(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	cache.GetTenderACLErr = errors.New("valkey down")
	restricted := usecase.NewRestrictedTenderSet(5 * time.Second)
	require.NoError(t, restricted.MarkRestricted(context.Background(), tenant, "tender-1"))
	org := &fixtures.FakeOrgMembershipClient{
		GetTenderACLFunc: func(ctx context.Context, tenant, tenderID, user string) (domain.TenderACL, error) {
			return domain.TenderACL{HasAccess: true, AccessLevel: domain.AccessLevelApprove}, nil
		},
	}
	checker := newTestChecker(cache, org, restricted)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "GET", TenderID: "tender-1", RequiredAccessLevel: domain.AccessLevelView},
	})

	assert.True(t, decision.Allow)
	assert.Equal(t, int64(1), org.TenderACLCalls)
}

func TestCheck_TenderACL_Allow_WhenSufficientGrant(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	restricted := usecase.NewRestrictedTenderSet(5 * time.Second)
	require.NoError(t, restricted.MarkRestricted(context.Background(), tenant, "tender-1"))
	org := &fixtures.FakeOrgMembershipClient{
		GetTenderACLFunc: func(ctx context.Context, tenant, tenderID, user string) (domain.TenderACL, error) {
			return domain.TenderACL{HasAccess: true, AccessLevel: domain.AccessLevelApprove}, nil
		},
	}
	checker := newTestChecker(cache, org, restricted)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: baseClaims(),
		Request: policy.RequestFacts{
			Method: "GET", TenderID: "tender-1", RequiredAccessLevel: domain.AccessLevelView,
		},
	})

	assert.True(t, decision.Allow)
}

func TestCheck_TenderACL_NotRestricted_SkipsOverlayEntirely(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	org := &fixtures.FakeOrgMembershipClient{} // GetTenderACLFunc left nil — must never be needed
	checker := newTestChecker(cache, org, nil) // tender-1 never marked restricted

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "GET", TenderID: "tender-1", RequiredAccessLevel: domain.AccessLevelEdit},
	})

	assert.True(t, decision.Allow, "default department membership is sufficient for a non-restricted tender")
	assert.Zero(t, org.TenderACLCalls)
}

func TestCheck_TenderACLFailure_FailsClosedForOverlayOnly(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	restricted := usecase.NewRestrictedTenderSet(5 * time.Second)
	require.NoError(t, restricted.MarkRestricted(context.Background(), tenant, "tender-1"))
	org := &fixtures.FakeOrgMembershipClient{
		GetTenderACLFunc: func(ctx context.Context, tenant, tenderID, user string) (domain.TenderACL, error) {
			return domain.TenderACL{}, domain.ErrUnavailable
		},
	}
	checker := newTestChecker(cache, org, restricted)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "GET", TenderID: "tender-1", RequiredAccessLevel: domain.AccessLevelView},
	})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyTenderACLInsufficient, decision.Reason, "§7 row 4: fails closed for the overlay only, never DENY_SERVICE_UNAVAILABLE")
}

func TestCheck_MFA_FreshAllowsStaleDenies(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	authTime := now.Add(-2 * time.Minute)

	newChecker := func() *usecase.Checker {
		cache := fixtures.NewFakeCache()
		cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
		cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
		org := &fixtures.FakeOrgMembershipClient{
			GetMFAFreshnessFunc: func(ctx context.Context, tenant string) (time.Duration, error) {
				return 5 * time.Minute, nil
			},
		}
		checker := newTestChecker(cache, org, nil)
		checker.SetClock(func() time.Time { return now })
		return checker
	}

	fresh := newChecker()
	decision := fresh.Check(context.Background(), usecase.CheckInput{
		Claims:  usecase.Claims{Subject: user, Issuer: dedicatedIssuer, AuthTime: authTime.Unix()},
		Request: policy.RequestFacts{Method: "POST", RequiredDepartmentLevel: policy.LevelApprover},
	})
	assert.True(t, decision.Allow, "auth_time within the freshness window must allow")

	staleAuthTime := now.Add(-10 * time.Minute)
	stale := newChecker()
	decision = stale.Check(context.Background(), usecase.CheckInput{
		Claims:  usecase.Claims{Subject: user, Issuer: dedicatedIssuer, AuthTime: staleAuthTime.Unix()},
		Request: policy.RequestFacts{Method: "POST", RequiredDepartmentLevel: policy.LevelApprover},
	})
	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyMFAStale, decision.Reason)
}

func TestCheck_MFA_NotRequired_SkipsFreshnessCallEntirely(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	org := &fixtures.FakeOrgMembershipClient{}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "GET"}, // no RequiredDepartmentLevel
	})

	assert.True(t, decision.Allow)
	assert.Zero(t, org.MFACalls, "§4.4: the MFA-freshness call must only run for the minority of approver-gated requests")
}

func TestCheck_MFAFreshnessCallFails_FailsClosed(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	org := &fixtures.FakeOrgMembershipClient{
		GetMFAFreshnessFunc: func(ctx context.Context, tenant string) (time.Duration, error) {
			return 0, domain.ErrUnavailable
		},
	}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "POST", RequiredDepartmentLevel: policy.LevelApprover},
	})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyMFAStale, decision.Reason)
}

// MFA freshness must never be cached — a dedicated regression test on top
// of the type-level one in internal/domain (§4.4/§8.3).
func TestCheck_MFAFreshness_NeverWrittenToCache(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	org := &fixtures.FakeOrgMembershipClient{
		GetMFAFreshnessFunc: func(ctx context.Context, tenant string) (time.Duration, error) { return 5 * time.Minute, nil },
	}
	checker := newTestChecker(cache, org, nil)

	checker.Check(context.Background(), usecase.CheckInput{
		Claims:  usecase.Claims{Subject: user, Issuer: dedicatedIssuer, AuthTime: time.Now().Unix()},
		Request: policy.RequestFacts{Method: "POST", RequiredDepartmentLevel: policy.LevelApprover},
	})

	for _, call := range cache.SortedCalls() {
		assert.NotContains(t, call, "SetMembershipContext", "MFA-gated request must not have re-written ae:ctx from a non-rebuild path")
	}
	assert.Equal(t, int64(1), org.MFACalls)
}

// §7 failure-handling matrix, end to end through Checker.

func TestCheck_Row1_ValkeyDown_SiblingHealthy_Bypass(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.CtxErr = errors.New("connection refused")
	cache.TenantErr = errors.New("connection refused")
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, error) {
			return domain.MembershipContext{Roles: []string{"tenant_admin"}}, domain.NewTenantContext(), nil
		},
	}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims(), Request: policy.RequestFacts{Method: "GET"}})

	assert.True(t, decision.Allow, "§7 row 1: Valkey down must bypass the cache, not fail closed, when the sibling is healthy")
	assert.Equal(t, int64(1), org.MembershipCalls)
}

func TestCheck_Row2_SiblingDown_ValkeyHealthy_ServesStale(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.MembershipContext{Roles: []string{"stale-role"}}, domain.CacheStale)
	cache.SeedTenantContext(tenant, domain.TenantContext{Plan: "stale-plan", FeatureFlags: []string{}}, domain.CacheStale)
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, error) {
			return domain.MembershipContext{}, domain.TenantContext{}, domain.ErrUnavailable
		},
	}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims(), Request: policy.RequestFacts{Method: "GET"}})

	require.True(t, decision.Allow, "§7 row 2: a stale entry must be served when the sibling is unreachable")
	assert.Equal(t, "stale-role", decision.Headers[domain.HeaderTenantRoles])
	assert.Equal(t, "stale-plan", decision.Headers[domain.HeaderPlan])
}

func TestCheck_Row2Degenerate_SiblingDown_NoStaleEntry_FailsClosed(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache() // nothing ever cached — a true Miss
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, error) {
			return domain.MembershipContext{}, domain.TenantContext{}, domain.ErrUnavailable
		},
	}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims()})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyServiceUnavailable, decision.Reason)
}

func TestCheck_Row3_BothDown_FailsClosed(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.CtxErr = errors.New("connection refused")
	cache.TenantErr = errors.New("connection refused")
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, error) {
			return domain.MembershipContext{}, domain.TenantContext{}, domain.ErrUnavailable
		},
	}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims()})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyServiceUnavailable, decision.Reason, "§9: 503-class, distinguishable from a 403 deny")
}

// Convergence-without-events: with the sibling healthy, an entry that has
// aged past its TTL (event delivery totally failed) must self-correct via
// plain read-through — this is a DIFFERENT code path from stale-if-error
// (Row2 above), which only serves stale when the sibling is unreachable.
// The doc is explicit these two must not be conflated.
func TestCheck_ConvergenceWithoutEvents_DistinctFromStaleIfError(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.MembershipContext{Roles: []string{"stale-role"}}, domain.CacheStale)
	cache.SeedTenantContext(tenant, domain.TenantContext{Plan: "stale-plan", FeatureFlags: []string{}}, domain.CacheStale)
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, error) {
			return domain.MembershipContext{Roles: []string{"fresh-role"}}, domain.TenantContext{Plan: "fresh-plan", FeatureFlags: []string{}}, nil
		},
	}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims(), Request: policy.RequestFacts{Method: "GET"}})

	require.True(t, decision.Allow)
	assert.Equal(t, "fresh-role", decision.Headers[domain.HeaderTenantRoles], "a healthy sibling must always win over a stale cache entry — TTL expiry alone never triggers stale-if-error serving")
	assert.Equal(t, "fresh-plan", decision.Headers[domain.HeaderPlan])
	assert.Equal(t, int64(1), org.MembershipCalls)
}

func TestCheck_SetCacheFailsAfterSiblingRebuild_StillAllows(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SetCtxErr = errors.New("valkey down")
	cache.SetTenantErr = errors.New("valkey down")
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, error) {
			return domain.MembershipContext{Roles: []string{"tenant_admin"}}, domain.NewTenantContext(), nil
		},
	}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims(), Request: policy.RequestFacts{Method: "GET"}})

	assert.True(t, decision.Allow, "a best-effort cache write failure after a successful rebuild must not affect the decision")
}

func TestNoopRecorder_AllMethodsAreSafeNoOps(t *testing.T) {
	t.Parallel()
	var r usecase.NoopRecorder
	r.ObserveDecision(domain.DenyRoleInsufficient, false)
	r.ObserveCacheHit(true)
	r.ObserveNegativeCacheHit(false)
	r.ObserveStaleIfErrorServed()
	r.ObserveSingleflightCoalesced()
	r.ObserveI8Latency(time.Millisecond)
	r.ObserveI12Latency(time.Millisecond)
	r.ObserveI14Latency(time.Millisecond)
	r.ObserveDecisionLatency(time.Millisecond)
}

func TestCheck_Singleflight_CoalescesConcurrentMisses(t *testing.T) {
	cache := fixtures.NewFakeCache()
	release := make(chan struct{})
	var callCount int64
	var mu sync.Mutex
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, error) {
			mu.Lock()
			callCount++
			mu.Unlock()
			<-release
			return domain.NewMembershipContext(), domain.NewTenantContext(), nil
		},
	}
	checker := newTestChecker(cache, org, nil)

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims(), Request: policy.RequestFacts{Method: "GET"}})
		}()
	}
	// Give every goroutine a chance to reach the in-flight rebuild call
	// before releasing it, so singleflight actually has something to coalesce.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	assert.Less(t, callCount, int64(n), "singleflight must coalesce concurrent rebuild calls for the same (tenant,user)")
}

// countingRecorder records only what TestCheck_MissingSubject_IsRecorded asserts.
type countingRecorder struct {
	usecase.NoopRecorder
	mu      sync.Mutex
	reasons []domain.DenyReason
}

func (r *countingRecorder) ObserveDecision(reason domain.DenyReason, allowed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !allowed {
		r.reasons = append(r.reasons, reason)
	}
}

// A request with no verified subject is denied inside Check — not in the gRPC
// adapter — so it is counted in iam_authz_enrichment_decisions_total like
// every other decision.
func TestCheck_MissingSubject_IsRecorded(t *testing.T) {
	t.Parallel()
	rec := &countingRecorder{}
	org := &fixtures.FakeOrgMembershipClient{}
	checker := usecase.NewChecker(fixtures.NewFakeCache(), org,
		usecase.NewRealmMap(map[string]string{dedicatedIssuer: tenant}, 5*time.Second),
		usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{}, rec, usecase.CheckerConfig{})

	decision := checker.Check(context.Background(), usecase.CheckInput{Claims: usecase.Claims{Issuer: dedicatedIssuer}})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyMalformedIdentity, decision.Reason)
	assert.Equal(t, []domain.DenyReason{domain.DenyMalformedIdentity}, rec.reasons)
	assert.Zero(t, org.MembershipCalls)
}

// Regression: a coalesced I-8 call must not inherit the first caller's
// cancellation. Request A is cancelled (e.g. Envoy's deadline) while B waits
// on the same singleflight key; B must still get A's successful result.
func TestCheck_Singleflight_FirstCallerCancelled_OthersUnaffected(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(ctx context.Context, _, _ string) (domain.MembershipContext, domain.TenantContext, error) {
			started <- struct{}{}
			select {
			case <-ctx.Done(): // the real HTTP client aborts on a cancelled request context
				return domain.MembershipContext{}, domain.TenantContext{}, domain.ErrUnavailable
			case <-release:
				return domain.MembershipContext{Roles: []string{"approver"}}, domain.TenantContext{Plan: "pro"}, nil
			}
		},
	}
	checker := newTestChecker(fixtures.NewFakeCache(), org, nil)

	ctxA, cancelA := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var decB domain.Decision
	wg.Add(2)
	go func() { defer wg.Done(); checker.Check(ctxA, usecase.CheckInput{Claims: baseClaims()}) }()
	<-started
	go func() {
		defer wg.Done()
		decB = checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims()})
	}()
	time.Sleep(50 * time.Millisecond) // B joins A's in-flight call
	cancelA()
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	assert.NotEqual(t, domain.DenyServiceUnavailable, decB.Reason, "a healthy request must not fail because another caller was cancelled")
	assert.Equal(t, int64(1), atomic.LoadInt64(&org.MembershipCalls), "still one coalesced I-8 call")
}

// ─── read_only in x-feature-flags (§4.6 gap-closure contract) ───────────────

// A cancelled-grace-period tenant: reads are allowed and x-feature-flags must
// carry "read_only" so downstream services (LLM, Workflow, Tender) can adapt
// their UI without a separate API call (IAM-to-Commercial §4.6).
func TestCheck_Allow_ReadOnly_AppendsToFeatureFlags(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.TenantContext{
		Plan:          "pro",
		FeatureFlags:  []string{"sso_enabled"},
		ReadOnly:      true,
		ResidencyMode: "standard",
	}, domain.CacheFresh)
	checker := newTestChecker(cache, &fixtures.FakeOrgMembershipClient{}, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "GET"},
	})

	require.True(t, decision.Allow)
	assert.Equal(t, "sso_enabled,read_only", decision.Headers[domain.HeaderFeatureFlags],
		"read_only sentinel must be appended to feature_flags on an allowed read for a cancelled-grace tenant")
}

// A non-cancelled tenant must never see "read_only" in x-feature-flags.
func TestCheck_Allow_NotReadOnly_NoSentinelInFeatureFlags(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.TenantContext{
		Plan:          "pro",
		FeatureFlags:  []string{"sso_enabled"},
		ReadOnly:      false,
		ResidencyMode: "standard",
	}, domain.CacheFresh)
	checker := newTestChecker(cache, &fixtures.FakeOrgMembershipClient{}, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "GET"},
	})

	require.True(t, decision.Allow)
	assert.NotContains(t, decision.Headers[domain.HeaderFeatureFlags], "read_only",
		"non-cancelled tenant must never have read_only in x-feature-flags")
}

// ─── CD-37: x-residency-mode header (LLD §16 AE-38) ─────────────────────────

// residencyCountingRecorder counts ObserveResidencyUnknown calls; all other
// methods are no-ops via the embedded NoopRecorder.
type residencyCountingRecorder struct {
	usecase.NoopRecorder
	mu    sync.Mutex
	count int
}

func (r *residencyCountingRecorder) ObserveResidencyUnknown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
}

func (r *residencyCountingRecorder) residencyUnknownCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

func allowedCheckWithResidency(residencyMode string) domain.Decision {
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.TenantContext{
		Plan:          "enterprise",
		FeatureFlags:  []string{},
		ResidencyMode: residencyMode,
	}, domain.CacheFresh)
	checker := newTestChecker(cache, &fixtures.FakeOrgMembershipClient{}, nil)
	return checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "GET"},
	})
}

func TestCheck_Allow_StandardResidency_HeaderInjected(t *testing.T) {
	t.Parallel()
	decision := allowedCheckWithResidency("standard")
	require.True(t, decision.Allow)
	assert.Equal(t, "standard", decision.Headers[domain.HeaderResidencyMode],
		"x-residency-mode must carry the tenant's value when it is 'standard'")
}

func TestCheck_Allow_StrictResidency_HeaderInjected(t *testing.T) {
	t.Parallel()
	decision := allowedCheckWithResidency("strict")
	require.True(t, decision.Allow)
	assert.Equal(t, "strict", decision.Headers[domain.HeaderResidencyMode],
		"x-residency-mode must carry the tenant's value when it is 'strict'")
}

func TestCheck_Allow_UnknownResidency_DefaultsToStrict_MetricIncremented(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	// Empty ResidencyMode simulates a pre-CD-37 Core or a stale cache entry.
	cache.SeedTenantContext(tenant, domain.TenantContext{FeatureFlags: []string{}}, domain.CacheFresh)

	rec := &residencyCountingRecorder{}
	realmMap := usecase.NewRealmMap(map[string]string{dedicatedIssuer: tenant}, 5*time.Second)
	checker := usecase.NewChecker(cache, &fixtures.FakeOrgMembershipClient{}, realmMap,
		usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{}, rec,
		usecase.CheckerConfig{SharedRealmIssuer: sharedRealmIssuer})

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "GET"},
	})

	require.True(t, decision.Allow)
	assert.Equal(t, "strict", decision.Headers[domain.HeaderResidencyMode],
		"unknown residency_mode must fail-safe to strict")
	assert.Equal(t, 1, rec.residencyUnknownCount(),
		"authz_residency_unknown_total must be incremented exactly once")
}

func TestCheck_Allow_UnknownResidency_ExplicitlyBadValue_DefaultsToStrict(t *testing.T) {
	t.Parallel()
	// A future Core revision sends an unrecognised value — still must be
	// treated as unknown and default to strict.
	decision := allowedCheckWithResidency("lax")
	require.True(t, decision.Allow)
	assert.Equal(t, "strict", decision.Headers[domain.HeaderResidencyMode])
}

func TestCheck_Deny_NoResidencyHeader(t *testing.T) {
	t.Parallel()
	// On a Deny path, buildHeaders is never called — no x-residency-mode must
	// appear in the decision's header map.
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.TenantContext{ReadOnly: true, FeatureFlags: []string{}, ResidencyMode: "strict"}, domain.CacheFresh)
	checker := newTestChecker(cache, &fixtures.FakeOrgMembershipClient{}, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "POST"},
	})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyTenantReadOnly, decision.Reason)
	assert.Empty(t, decision.Headers, "deny decisions must carry no injected headers")
}

// ─── CD-28: dedicated_workflow_queue in x-feature-flags (LLD §16 AE-39) ─────

// No new infrastructure is needed: flags arrive from Core's feature_flags[]
// slice and flow through the existing x-feature-flags header unchanged.
// This test pins that a tenant with the flag gets it in the header.
func TestCheck_Allow_DedicatedWorkflowQueue_InFeatureFlags(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.TenantContext{
		Plan:          "enterprise",
		FeatureFlags:  []string{"sso_enabled", "dedicated_workflow_queue"},
		ResidencyMode: "standard",
	}, domain.CacheFresh)
	checker := newTestChecker(cache, &fixtures.FakeOrgMembershipClient{}, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  baseClaims(),
		Request: policy.RequestFacts{Method: "GET"},
	})

	require.True(t, decision.Allow)
	flags := decision.Headers[domain.HeaderFeatureFlags]
	assert.Contains(t, flags, "dedicated_workflow_queue",
		"an enterprise tenant with dedicated_workflow_queue grant must see it in x-feature-flags")
	assert.Contains(t, flags, "sso_enabled", "other flags must also be present")
}

// ─── CD-31: deny-code stability (LLD §16 AE-40) ──────────────────────────────

// Pin the exact wire strings for every DenyReason. A future RFC 9457 migration
// (CD-31) must not change these values — they are part of this service's
// versioned runtime contract (VERSIONING.md).
func TestDenyCodes_Pinned(t *testing.T) {
	t.Parallel()
	cases := []struct {
		reason domain.DenyReason
		want   string
		status int
	}{
		{domain.DenyUnresolvableSubject, "DENY_UNRESOLVABLE_SUBJECT", 403},
		{domain.DenyTenantReadOnly, "DENY_TENANT_READ_ONLY", 403},
		{domain.DenyMFAStale, "DENY_MFA_STALE", 403},
		{domain.DenyTenderACLInsufficient, "DENY_TENDER_ACL_INSUFFICIENT", 403},
		{domain.DenyRoleInsufficient, "DENY_ROLE_INSUFFICIENT", 403},
		{domain.DenyServiceUnavailable, "DENY_SERVICE_UNAVAILABLE", 503},
		{domain.DenyMalformedIdentity, "DENY_MALFORMED_IDENTITY", 401},
	}
	for _, tc := range cases {
		t.Run(string(tc.reason), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, string(tc.reason),
				"DenyReason wire value is part of the versioned contract and must not change")
			assert.Equal(t, tc.status, tc.reason.HTTPStatus(),
				"HTTP status mapping for %s must not change", tc.reason)
		})
	}
}

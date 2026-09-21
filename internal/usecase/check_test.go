package usecase_test

import (
	"context"
	"errors"
	"sync"
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

// TC-021: ae:ctx fresh but ae:tenant missing (e.g. after a billing event
// evicts only ae:tenant). The double-fresh guard fails so the sibling is
// called and both ae:ctx and ae:tenant are re-written. This is the actual
// behavior — the code does not skip ae:ctx re-write when it was already
// fresh; it always writes both on a successful sibling rebuild.
func TestCheck_AsymmetricCache_CtxFreshTenantMiss_RebuildsBoth(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.MembershipContext{
		Roles: []string{"tenant_admin"}, Departments: []domain.Department{},
	}, domain.CacheFresh)
	// ae:tenant deliberately NOT seeded → miss → double-fresh guard fails
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(ctx context.Context, _, _ string) (domain.MembershipContext, domain.TenantContext, error) {
			return domain.MembershipContext{Roles: []string{"tenant_admin"}, Departments: []domain.Department{}},
				domain.NewTenantContext(), nil
		},
	}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: baseClaims(), Request: policy.RequestFacts{Method: "GET"},
	})

	require.True(t, decision.Allow)
	assert.Equal(t, int64(1), org.MembershipCalls, "sibling must be called when ae:tenant is missing")
	assert.Contains(t, cache.SortedCalls(), "SetTenantContext:"+tenant, "ae:tenant must be written after rebuild")
	assert.Contains(t, cache.SortedCalls(), "SetMembershipContext:"+tenant+":"+user,
		"ae:ctx is also re-written after rebuild (code always writes both — even if ae:ctx was already fresh)")
}

// TC-030: GetNegative errors while Valkey reachable — silently skips the
// negative-cache gate and falls through to the sibling call.
func TestCheck_GetNegativeError_SkipsNegativeGate_CallsSibling(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.NegErr = errors.New("valkey neg error")
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(ctx context.Context, _, _ string) (domain.MembershipContext, domain.TenantContext, error) {
			return domain.MembershipContext{Roles: []string{"tenant_admin"}, Departments: []domain.Department{}},
				domain.NewTenantContext(), nil
		},
	}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: baseClaims(), Request: policy.RequestFacts{Method: "GET"},
	})

	require.True(t, decision.Allow, "GetNegative error must not deny — sibling is called instead")
	assert.Equal(t, int64(1), org.MembershipCalls, "sibling must be called when GetNegative errors")
}

// TC-051: context.DeadlineExceeded from the tender-ACL sibling must fail
// closed with DenyTenderACLInsufficient (§7 row 4).
func TestCheck_TenderACL_ContextDeadlineExceeded_FailsClosed(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	restricted := usecase.NewRestrictedTenderSet(5 * time.Second)
	require.NoError(t, restricted.MarkRestricted(context.Background(), tenant, "tender-1"))
	org := &fixtures.FakeOrgMembershipClient{
		GetTenderACLFunc: func(ctx context.Context, _, _, _ string) (domain.TenderACL, error) {
			return domain.TenderACL{}, context.DeadlineExceeded
		},
	}
	checker := newTestChecker(cache, org, restricted)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: baseClaims(),
		Request: policy.RequestFacts{
			Method: "GET", TenderID: "tender-1", RequiredAccessLevel: domain.AccessLevelView,
		},
	})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyTenderACLInsufficient, decision.Reason,
		"context deadline on tender-ACL sibling must fail closed, not DENY_SERVICE_UNAVAILABLE")
}

// TC-052: stale cache entry + sibling returns 404 — must deny and write the
// negative sentinel, never serve the stale entry.
func TestCheck_StaleCache_Sibling404_DeniesAndSetsNegative(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.MembershipContext{Roles: []string{"stale-role"}, Departments: []domain.Department{}}, domain.CacheStale)
	cache.SeedTenantContext(tenant, domain.TenantContext{Plan: "stale-plan", FeatureFlags: []string{}}, domain.CacheStale)
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(ctx context.Context, _, _ string) (domain.MembershipContext, domain.TenantContext, error) {
			return domain.MembershipContext{}, domain.TenantContext{}, domain.ErrNotFound
		},
	}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims()})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyUnresolvableSubject, decision.Reason,
		"sibling 404 must deny even when a stale entry exists — never serve stale on authoritative 404")
	assert.Contains(t, cache.SortedCalls(), "SetNegative:"+tenant+":"+user,
		"negative sentinel must be written so the next request short-circuits without re-calling the sibling")
}

// TC-053: all N goroutines coalesced by singleflight into one sibling call
// that returns an error — every caller must receive DenyServiceUnavailable.
func TestCheck_Singleflight_AllCoalescedCallersGetError(t *testing.T) {
	cache := fixtures.NewFakeCache()
	release := make(chan struct{})
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(ctx context.Context, _, _ string) (domain.MembershipContext, domain.TenantContext, error) {
			<-release
			return domain.MembershipContext{}, domain.TenantContext{}, domain.ErrUnavailable
		},
	}
	checker := newTestChecker(cache, org, nil)

	const n = 10
	decisions := make([]domain.Decision, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(idx int) {
			defer wg.Done()
			decisions[idx] = checker.Check(context.Background(), usecase.CheckInput{Claims: baseClaims()})
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, d := range decisions {
		assert.False(t, d.Allow, "goroutine %d: all coalesced callers must be denied when sibling errors", i)
		assert.Equal(t, domain.DenyServiceUnavailable, d.Reason,
			"goroutine %d: reason must be DENY_SERVICE_UNAVAILABLE", i)
	}
	assert.Less(t, org.MembershipCalls, int64(n), "singleflight must coalesce — fewer than n sibling calls made")
}

// TC-022: a user with no department memberships must get x-departments=”
// (empty string) in the Allow headers, not a missing or nil entry.
func TestCheck_Headers_ZeroDepartments(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.MembershipContext{
		Roles:       []string{"tenant_admin"},
		Departments: []domain.Department{},
	}, domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.TenantContext{Plan: "pro", FeatureFlags: []string{}}, domain.CacheFresh)
	checker := newTestChecker(cache, &fixtures.FakeOrgMembershipClient{}, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: baseClaims(), Request: policy.RequestFacts{Method: "GET"},
	})

	require.True(t, decision.Allow)
	assert.Equal(t, "", decision.Headers[domain.HeaderDepartments],
		"empty departments slice must produce x-departments='' (empty string)")
}

// TC-023: multiple departments must be comma-joined in x-departments as
// dept-id:level,dept-id:level, preserving insertion order from the slice.
func TestCheck_Headers_MultipleDepartmentsCommaJoined(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.MembershipContext{
		Roles: []string{},
		Departments: []domain.Department{
			{DepartmentID: "dept-finance", Level: "reviewer"},
			{DepartmentID: "dept-legal", Level: "approver"},
		},
	}, domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	checker := newTestChecker(cache, &fixtures.FakeOrgMembershipClient{}, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: baseClaims(), Request: policy.RequestFacts{Method: "GET"},
	})

	require.True(t, decision.Allow)
	assert.Equal(t, "dept-finance:reviewer,dept-legal:approver", decision.Headers[domain.HeaderDepartments])
}

// TC-024: multiple tenant-level roles must be comma-joined in x-tenant-roles.
func TestCheck_Headers_MultipleRolesCommaJoined(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.MembershipContext{
		Roles: []string{"tenant_admin", "tender_admin"}, Departments: []domain.Department{},
	}, domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	checker := newTestChecker(cache, &fixtures.FakeOrgMembershipClient{}, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: baseClaims(), Request: policy.RequestFacts{Method: "GET"},
	})

	require.True(t, decision.Allow)
	assert.Equal(t, "tenant_admin,tender_admin", decision.Headers[domain.HeaderTenantRoles])
}

// TC-025: auth_time=0 (missing claim → year 1970) with the MFA gate active
// must always deny — now-0 is enormous and always exceeds any window.
func TestCheck_MFA_AuthTimeZero_AlwaysDenies(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	org := &fixtures.FakeOrgMembershipClient{
		GetMFAFreshnessFunc: func(_ context.Context, _ string) (time.Duration, error) {
			return 5 * time.Minute, nil
		},
	}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  usecase.Claims{Subject: user, Issuer: dedicatedIssuer, AuthTime: 0},
		Request: policy.RequestFacts{Method: "POST", RequiredDepartmentLevel: policy.LevelApprover},
	})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyMFAStale, decision.Reason,
		"auth_time=0 (year 1970) is always outside any practical freshness window")
}

// TC-026: checkMFAFreshness uses > (strict), so auth_time exactly equal to
// now-window must Allow (TC-026a) and one second past must Deny (TC-026b).
func TestCheck_MFA_ExactWindowEdge_Allows(t *testing.T) {
	t.Parallel()
	window := 2 * time.Minute
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	newMFAChecker := func() *usecase.Checker {
		cache := fixtures.NewFakeCache()
		cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
		cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
		org := &fixtures.FakeOrgMembershipClient{
			GetMFAFreshnessFunc: func(_ context.Context, _ string) (time.Duration, error) {
				return window, nil
			},
		}
		c := newTestChecker(cache, org, nil)
		c.SetClock(func() time.Time { return now })
		return c
	}

	exactEdge := now.Add(-window)
	decision := newMFAChecker().Check(context.Background(), usecase.CheckInput{
		Claims:  usecase.Claims{Subject: user, Issuer: dedicatedIssuer, AuthTime: exactEdge.Unix()},
		Request: policy.RequestFacts{Method: "POST", RequiredDepartmentLevel: policy.LevelApprover},
	})
	assert.True(t, decision.Allow, "TC-026a: auth_time exactly at the window edge must Allow (> not >=)")

	oneSecondPast := now.Add(-window - time.Second)
	decision = newMFAChecker().Check(context.Background(), usecase.CheckInput{
		Claims:  usecase.Claims{Subject: user, Issuer: dedicatedIssuer, AuthTime: oneSecondPast.Unix()},
		Request: policy.RequestFacts{Method: "POST", RequiredDepartmentLevel: policy.LevelApprover},
	})
	assert.False(t, decision.Allow, "TC-026b: one second past window must Deny")
	assert.Equal(t, domain.DenyMFAStale, decision.Reason)
}

// TC-036: when SharedRealmIssuer is empty the shared-realm fallback is
// disabled; an issuer not in the explicit realm map must DENY_MALFORMED_IDENTITY
// even if the token carries a tenant_id claim.
func TestCheck_SharedRealmIssuerEmpty_UnknownIssuerDenies(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	realmMap := usecase.NewRealmMap(map[string]string{dedicatedIssuer: tenant}, 5*time.Second)
	checker := usecase.NewChecker(cache, &fixtures.FakeOrgMembershipClient{}, realmMap,
		usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{}, usecase.NoopRecorder{},
		usecase.CheckerConfig{SharedRealmIssuer: ""},
	)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: usecase.Claims{
			Subject:  user,
			Issuer:   sharedRealmIssuer, // not in realm map; shared-realm fallback disabled
			TenantID: tenant,
		},
	})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyMalformedIdentity, decision.Reason,
		"SharedRealmIssuer='' means the shared-realm fallback is off — unknown issuer must deny")
}

// TC-038: an unrecognized required_department_level value (e.g. "senior_reviewer")
// must not trigger the MFA gate — RequiresApproverGate fires only on the
// exact string "approver".
func TestCheck_UnknownRequiredDepartmentLevel_SkipsMFAGate(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	org := &fixtures.FakeOrgMembershipClient{}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: baseClaims(),
		Request: policy.RequestFacts{
			Method:                  "POST",
			RequiredDepartmentLevel: "senior_reviewer",
		},
	})

	assert.True(t, decision.Allow)
	assert.Zero(t, org.MFACalls, "unrecognized department level must not trigger the MFA freshness call")
}

// TC-047: every Allow decision must carry exactly the six InjectedHeaders,
// all non-empty when the membership/tenant data is populated.
func TestCheck_AllSixHeadersPresentAndNonEmptyOnAllow(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.MembershipContext{
		Roles:       []string{"tenant_admin"},
		Departments: []domain.Department{{DepartmentID: "eng", Level: "reviewer"}},
	}, domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.TenantContext{Plan: "pro", FeatureFlags: []string{"beta"}}, domain.CacheFresh)
	checker := newTestChecker(cache, &fixtures.FakeOrgMembershipClient{}, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: baseClaims(), Request: policy.RequestFacts{Method: "GET"},
	})

	require.True(t, decision.Allow)
	for _, hdr := range []string{
		domain.HeaderTenantID, domain.HeaderUserID, domain.HeaderDepartments,
		domain.HeaderTenantRoles, domain.HeaderPlan, domain.HeaderFeatureFlags,
	} {
		val, ok := decision.Headers[hdr]
		assert.True(t, ok, "Allow decision must include header %q", hdr)
		assert.NotEmpty(t, val, "Allow decision must have a non-empty value for %q", hdr)
	}
}

// TC-049: GetMFAFreshness returning window=0 means any auth_time in the
// past is stale (now - authTime > 0 for any auth_time before now).
func TestCheck_MFA_WindowZero_AlwaysDenies(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.NewMembershipContext(), domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.NewTenantContext(), domain.CacheFresh)
	org := &fixtures.FakeOrgMembershipClient{
		GetMFAFreshnessFunc: func(_ context.Context, _ string) (time.Duration, error) {
			return 0, nil
		},
	}
	checker := newTestChecker(cache, org, nil)
	checker.SetClock(func() time.Time { return now })

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  usecase.Claims{Subject: user, Issuer: dedicatedIssuer, AuthTime: now.Add(-time.Second).Unix()},
		Request: policy.RequestFacts{Method: "POST", RequiredDepartmentLevel: policy.LevelApprover},
	})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyMFAStale, decision.Reason,
		"window=0: any auth_time in the past exceeds the zero-length window")
}

// TC-043: a shared-realm JWT whose tenant_id contains a colon resolves to
// that tenant string. The x-tenant-id header must reflect the resolved
// tenant exactly — not bleed into an adjacent tenant whose name shares a
// prefix before the colon.
func TestCheck_SEC_TenantIDWithColon_HeaderReflectsResolvedTenant(t *testing.T) {
	t.Parallel()
	colonTenant := "hotel-abc:extra"
	cache := fixtures.NewFakeCache()
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(_ context.Context, _, _ string) (domain.MembershipContext, domain.TenantContext, error) {
			return domain.MembershipContext{Roles: []string{}, Departments: []domain.Department{}},
				domain.NewTenantContext(), nil
		},
	}
	realmMap := usecase.NewRealmMap(nil, 5*time.Second)
	checker := usecase.NewChecker(cache, org, realmMap, usecase.NewRestrictedTenderSet(5*time.Second),
		fixtures.NoopLogger{}, usecase.NoopRecorder{},
		usecase.CheckerConfig{SharedRealmIssuer: sharedRealmIssuer},
	)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  usecase.Claims{Subject: user, Issuer: sharedRealmIssuer, TenantID: colonTenant},
		Request: policy.RequestFacts{Method: "GET"},
	})

	require.True(t, decision.Allow)
	assert.Equal(t, colonTenant, decision.Headers[domain.HeaderTenantID],
		"SEC-1: x-tenant-id must reflect the resolved tenant, never a neighbouring tenant whose name shares a key prefix")
}

// TC-044: a JWT whose issuer is not in the realm map (and SharedRealmIssuer
// is different) must DENY_MALFORMED_IDENTITY regardless of any tenant_id
// wildcard value in the token.
func TestCheck_SEC_UnknownIssuer_DeniesRegardlessOfTenantIDClaim(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	realmMap := usecase.NewRealmMap(map[string]string{dedicatedIssuer: tenant}, 5*time.Second)
	checker := usecase.NewChecker(cache, &fixtures.FakeOrgMembershipClient{}, realmMap,
		usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{}, usecase.NoopRecorder{},
		usecase.CheckerConfig{SharedRealmIssuer: sharedRealmIssuer},
	)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: usecase.Claims{Subject: user, Issuer: "https://evil.example.com/realms/attack", TenantID: "hotel*"},
	})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyMalformedIdentity, decision.Reason,
		"SEC-1: an issuer not in the realm map must deny regardless of tenant_id claim value")
}

// TC-045: a user whose sub claim contains a colon is treated as a normal
// user: the colon is part of their ID, the org lookup fails if they don't
// exist, and they are correctly denied without confusing another user's data.
func TestCheck_SEC_SubWithColon_TreatedAsNormalUser(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	org := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(_ context.Context, _, _ string) (domain.MembershipContext, domain.TenantContext, error) {
			return domain.MembershipContext{}, domain.TenantContext{}, domain.ErrNotFound
		},
	}
	checker := newTestChecker(cache, org, nil)

	decision := checker.Check(context.Background(), usecase.CheckInput{
		Claims: usecase.Claims{Subject: "tenant-2:alice", Issuer: dedicatedIssuer},
	})

	assert.False(t, decision.Allow)
	assert.Equal(t, domain.DenyUnresolvableSubject, decision.Reason,
		"SEC-2: sub with colon must not grant cross-tenant access — it is looked up as a normal user ID that happens not to exist")
}

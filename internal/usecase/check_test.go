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

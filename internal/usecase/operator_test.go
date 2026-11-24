package usecase_test

import (
	"context"
	"strings"
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

// CD-52 operator path (LLD §8.9).

const (
	operatorIssuer = "https://kc.example.com/realms/platform"
	operatorSub    = "7f1c2a9e-0b6d-4c3e-9a51-2f8e4d6b1c07"
	targetTenant   = "3b9d6c2e-5a14-4f7b-8e21-9c0a7d3f6e58"
)

type capturingLogger struct {
	mu    sync.Mutex
	infos []map[string]interface{}
}

func (l *capturingLogger) Debug(string, map[string]interface{}) {}
func (l *capturingLogger) Warn(string, map[string]interface{})  {}
func (l *capturingLogger) Error(string, map[string]interface{}) {}
func (l *capturingLogger) Info(msg string, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if msg == "operator_access" {
		l.infos = append(l.infos, fields)
	}
}

func newOperatorChecker(org usecase.OrgMembershipClient, log usecase.Logger, operatorIssuerCfg string) *usecase.Checker {
	realmMap := usecase.NewRealmMap(map[string]string{dedicatedIssuer: tenant}, 5*time.Second)
	return usecase.NewChecker(fixtures.NewFakeCache(), org, realmMap, usecase.NewRestrictedTenderSet(5*time.Second),
		log, usecase.NoopRecorder{}, usecase.CheckerConfig{
			SharedRealmIssuer: sharedRealmIssuer,
			OperatorIssuer:    operatorIssuerCfg,
		})
}

func operatorInput(method, path string, roles ...string) usecase.CheckInput {
	return usecase.CheckInput{
		Claims:  usecase.Claims{Subject: operatorSub, Issuer: operatorIssuer, Roles: roles},
		Request: policy.RequestFacts{Method: method, Path: path},
	}
}

func TestOperator_TenantRoute_AllowedWithPathTenantAndRole(t *testing.T) {
	t.Parallel()
	org := &fixtures.FakeOrgMembershipClient{}
	log := &capturingLogger{}
	checker := newOperatorChecker(org, log, operatorIssuer)

	d := checker.Check(context.Background(),
		operatorInput("PUT", "/api/v1/operator/tenants/"+targetTenant+"/trial-profile?x=1", domain.PlatformOperatorRole, "offline_access"))

	require.True(t, d.Allow)
	assert.Equal(t, map[string]string{
		domain.HeaderTenantID:      targetTenant,
		domain.HeaderUserID:        operatorSub,
		domain.HeaderTenantRoles:   domain.PlatformOperatorRole + ",offline_access",
		domain.HeaderDepartments:   "",
		domain.HeaderPlan:          "",
		domain.HeaderFeatureFlags:  "",
		domain.HeaderResidencyMode: "",
	}, d.Headers, "all seven trusted headers set; all platform-realm roles forwarded in x-tenant-roles (A-10)")
	assert.Zero(t, org.MembershipCalls, "an operator is not a tenant member — no I-8 lookup")

	require.Len(t, log.infos, 1, "every operator decision is audit-logged")
	assert.Equal(t, operatorSub, log.infos[0]["operator_sub"])
	assert.Equal(t, targetTenant, log.infos[0]["tenant"])
	assert.Equal(t, "/api/v1/operator/tenants/"+targetTenant+"/trial-profile", log.infos[0]["path"], "query string not logged")
}

func TestOperator_RouteWithoutTenant_GetsNilTenant(t *testing.T) {
	t.Parallel()
	checker := newOperatorChecker(&fixtures.FakeOrgMembershipClient{}, fixtures.NoopLogger{}, operatorIssuer)

	for _, path := range []string{
		"/api/v1/operator/billing/reconciliation-runs",
		"/api/v1/operator/plans/pro",
		"/api/v1/operator/tenants",
	} {
		d := checker.Check(context.Background(), operatorInput("POST", path, domain.PlatformOperatorRole))
		require.True(t, d.Allow, path)
		assert.Equal(t, domain.NilTenantID, d.Headers[domain.HeaderTenantID], path)
	}
}

func TestOperator_DeniedOutsideOperatorRoutes(t *testing.T) {
	t.Parallel()
	log := &capturingLogger{}
	checker := newOperatorChecker(&fixtures.FakeOrgMembershipClient{}, log, operatorIssuer)

	for _, path := range []string{
		"/api/v1/tenants/" + targetTenant + "/members",
		"/api/v1/internal/tenants/" + targetTenant + "/seat-usage",
		"/api/v1/operatorX/tenants/" + targetTenant,
		"/api/v1/operator",
	} {
		d := checker.Check(context.Background(), operatorInput("GET", path, domain.PlatformOperatorRole))
		assert.False(t, d.Allow, path)
		assert.Equal(t, domain.DenyRoleInsufficient, d.Reason, path)
	}
	assert.Len(t, log.infos, 4, "denials are audit-logged too")
	assert.Equal(t, string(domain.DenyRoleInsufficient), log.infos[0]["reason"])
}

func TestOperator_WithoutPlatformOperatorRole_Denied(t *testing.T) {
	t.Parallel()
	checker := newOperatorChecker(&fixtures.FakeOrgMembershipClient{}, fixtures.NoopLogger{}, operatorIssuer)

	for name, roles := range map[string][]string{
		"no_roles":   nil,
		"other_role": {"commercial_trial_manager", "offline_access"},
	} {
		d := checker.Check(context.Background(), operatorInput("PUT", "/api/v1/operator/tenants/"+targetTenant+"/trial-profile", roles...))
		assert.False(t, d.Allow, name)
		assert.Equal(t, domain.DenyRoleInsufficient, d.Reason, name)
	}
}

func TestOperator_MalformedSubjectOrTenantSegment_Denied(t *testing.T) {
	t.Parallel()
	checker := newOperatorChecker(&fixtures.FakeOrgMembershipClient{}, fixtures.NoopLogger{}, operatorIssuer)

	in := operatorInput("GET", "/api/v1/operator/tenants/"+targetTenant+"/entitlements", domain.PlatformOperatorRole)
	in.Claims.Subject = "not-a-uuid"
	assert.Equal(t, domain.DenyMalformedIdentity, checker.Check(context.Background(), in).Reason)

	for _, seg := range []string{"acme", "", domain.NilTenantID} {
		d := checker.Check(context.Background(), operatorInput("GET", "/api/v1/operator/tenants/"+seg+"/entitlements", domain.PlatformOperatorRole))
		assert.Equal(t, domain.DenyMalformedIdentity, d.Reason, "tenant segment %q", seg)
	}
}

// A tenant token on an operator route gains nothing: only the operator path
// ever injects platform_operator, and a tenant token never takes it — even
// if the token itself claims the role.
func TestOperator_TenantTokenOnOperatorRoute_NeverGetsOperatorRole(t *testing.T) {
	t.Parallel()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(tenant, user, domain.MembershipContext{Roles: []string{"tenant_admin"}}, domain.CacheFresh)
	cache.SeedTenantContext(tenant, domain.TenantContext{Plan: "pro", ResidencyMode: "standard"}, domain.CacheFresh)
	checker := usecase.NewChecker(cache, &fixtures.FakeOrgMembershipClient{},
		usecase.NewRealmMap(map[string]string{dedicatedIssuer: tenant}, 5*time.Second),
		usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{}, usecase.NoopRecorder{},
		usecase.CheckerConfig{SharedRealmIssuer: sharedRealmIssuer, OperatorIssuer: operatorIssuer})

	d := checker.Check(context.Background(), usecase.CheckInput{
		Claims:  usecase.Claims{Subject: user, Issuer: dedicatedIssuer, Roles: []string{domain.PlatformOperatorRole}},
		Request: policy.RequestFacts{Method: "PUT", Path: "/api/v1/operator/tenants/" + targetTenant + "/trial-profile"},
	})
	if d.Allow {
		assert.NotContains(t, d.Headers[domain.HeaderTenantRoles], domain.PlatformOperatorRole)
		assert.Equal(t, tenant, d.Headers[domain.HeaderTenantID], "tenant token keeps its own tenant, not the path's")
	}
}

// AE-TND-F1 / §16 AE-49: operator tokens must inject x-auth-time the same way
// tenant tokens do so downstream services (e.g. Tender Service reading
// mfa_verified_at) receive a consistent header on both paths.

func TestOperator_AuthTime_NonZero_HeaderInjected(t *testing.T) {
	t.Parallel()
	checker := newOperatorChecker(&fixtures.FakeOrgMembershipClient{}, fixtures.NoopLogger{}, operatorIssuer)

	const authTime int64 = 1699000000
	in := usecase.CheckInput{
		Claims: usecase.Claims{
			Subject:  operatorSub,
			Issuer:   operatorIssuer,
			Roles:    []string{domain.PlatformOperatorRole},
			AuthTime: authTime,
		},
		Request: policy.RequestFacts{Method: "GET", Path: "/api/v1/operator/tenants/" + targetTenant + "/entitlements"},
	}
	d := checker.Check(context.Background(), in)

	require.True(t, d.Allow)
	want := time.Unix(authTime, 0).UTC().Format(time.RFC3339)
	assert.Equal(t, want, d.Headers[domain.HeaderAuthTime],
		"x-auth-time must be injected as RFC 3339 UTC for operator tokens with non-zero auth_time (AE-TND-F1)")
}

func TestOperator_AuthTime_Zero_HeaderAbsent(t *testing.T) {
	t.Parallel()
	checker := newOperatorChecker(&fixtures.FakeOrgMembershipClient{}, fixtures.NoopLogger{}, operatorIssuer)

	in := usecase.CheckInput{
		Claims: usecase.Claims{
			Subject:  operatorSub,
			Issuer:   operatorIssuer,
			Roles:    []string{domain.PlatformOperatorRole},
			AuthTime: 0,
		},
		Request: policy.RequestFacts{Method: "GET", Path: "/api/v1/operator/tenants/" + targetTenant + "/entitlements"},
	}
	d := checker.Check(context.Background(), in)

	require.True(t, d.Allow)
	_, hasAuthTime := d.Headers[domain.HeaderAuthTime]
	assert.False(t, hasAuthTime, "x-auth-time must be absent when auth_time is zero")
}

func TestOperator_PathDisabled_OperatorTokenDeniedAsBefore(t *testing.T) {
	t.Parallel()
	checker := newOperatorChecker(&fixtures.FakeOrgMembershipClient{}, fixtures.NoopLogger{}, "")

	d := checker.Check(context.Background(), operatorInput("GET", "/api/v1/operator/plans", domain.PlatformOperatorRole))
	assert.False(t, d.Allow)
	assert.Equal(t, domain.DenyMalformedIdentity, d.Reason)
}

// billingOperatorRoutes are Commercial Billing's operator routes B-O1..B-O15
// (Billing LLD §5.3; BL-OQ-9). AuthZ admits the whole /api/v1/operator/
// prefix, so no route list exists here: these tests pin that every Billing
// path is admitted with the right tenant header and refused without the role.
var billingOperatorRoutes = []struct {
	id, method, path string
	tenantInPath     bool
}{
	{"B-O1", "POST", "/api/v1/operator/tenants/" + targetTenant + "/conversions", true},
	{"B-O2", "POST", "/api/v1/operator/tenants/" + targetTenant + "/adjustments", true},
	{"B-O3", "POST", "/api/v1/operator/tenants/" + targetTenant + "/refunds", true},
	{"B-O4", "GET", "/api/v1/operator/tenants/" + targetTenant + "/invoices", true},
	{"B-O5", "POST", "/api/v1/operator/billing/reconciliation-runs", false},
	{"B-O6", "GET", "/api/v1/operator/billing/reconciliation-runs/0193a8f0-1c2d-7e3f-9a4b-5c6d7e8f9a0b", false},
	{"B-O7", "GET", "/api/v1/operator/tenants/" + targetTenant + "/subscription", true},
	{"B-O8", "POST", "/api/v1/operator/tenants/" + targetTenant + "/conversion-reversals", true},
	{"B-O9", "POST", "/api/v1/operator/tenants/" + targetTenant + "/conversion-sagas/0193a8f0-1c2d-7e3f-9a4b-5c6d7e8f9a0c/actions", true},
	{"B-O10", "PUT", "/api/v1/operator/tenants/" + targetTenant + "/collection-pause", true},
	{"B-O11", "POST", "/api/v1/operator/billing/plan-prices", false},
	{"B-O12", "POST", "/api/v1/operator/billing/token-packs", false},
	{"B-O13", "POST", "/api/v1/operator/billing/webhook-events/stripe/evt_1QabcDEF/replay", false},
	{"B-O14", "POST", "/api/v1/operator/billing/provider-certifications", false},
	{"B-O15", "POST", "/api/v1/operator/billing/provider-certifications/0193a8f0-1c2d-7e3f-9a4b-5c6d7e8f9a0d/revoke", false},
}

func TestOperator_BillingRoutes_AllowedWithRole(t *testing.T) {
	t.Parallel()
	checker := newOperatorChecker(&fixtures.FakeOrgMembershipClient{}, fixtures.NoopLogger{}, operatorIssuer)
	for _, r := range billingOperatorRoutes {
		d := checker.Check(context.Background(), operatorInput(r.method, r.path, domain.PlatformOperatorRole))
		require.True(t, d.Allow, "%s %s %s: %s", r.id, r.method, r.path, d.Reason)
		want := domain.NilTenantID
		if r.tenantInPath {
			want = targetTenant
		}
		assert.Equal(t, want, d.Headers[domain.HeaderTenantID], r.id)
		assert.Equal(t, operatorSub, d.Headers[domain.HeaderUserID], r.id)
		assert.Equal(t, domain.PlatformOperatorRole, d.Headers[domain.HeaderTenantRoles], r.id)
	}
}

func TestOperator_BillingRoutes_DeniedWithoutRole(t *testing.T) {
	t.Parallel()
	checker := newOperatorChecker(&fixtures.FakeOrgMembershipClient{}, fixtures.NoopLogger{}, operatorIssuer)
	for _, r := range billingOperatorRoutes {
		d := checker.Check(context.Background(), operatorInput(r.method, r.path, "commercial_trial_manager"))
		assert.False(t, d.Allow, r.id)
		assert.Equal(t, domain.DenyRoleInsufficient, d.Reason, r.id)
	}
}

func TestOperator_BillingTenantRoutes_MalformedTenantDenied(t *testing.T) {
	t.Parallel()
	checker := newOperatorChecker(&fixtures.FakeOrgMembershipClient{}, fixtures.NoopLogger{}, operatorIssuer)
	for _, r := range billingOperatorRoutes {
		if !r.tenantInPath {
			continue
		}
		path := strings.Replace(r.path, targetTenant, "acme", 1)
		d := checker.Check(context.Background(), operatorInput(r.method, path, domain.PlatformOperatorRole))
		assert.False(t, d.Allow, r.id)
		assert.Equal(t, domain.DenyMalformedIdentity, d.Reason, r.id)
	}
}

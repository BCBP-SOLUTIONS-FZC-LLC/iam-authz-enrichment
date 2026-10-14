//go:build e2e

package e2e

import (
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// buildCheckRequest constructs a CheckRequest the same way Envoy's
// jwt_authn + ext_authz filters would: verified claims under
// metadata_context (never a header — see claims.go's doc comment on why
// that distinction is this service's core security invariant), plus
// route-level context_extensions.
func buildCheckRequest(t *testing.T, sub, tenant string, authTime int64, method, path string, ext map[string]string) *authv3.CheckRequest {
	t.Helper()
	claims := map[string]any{"sub": sub, "iss": e2eTestIssuer}
	if tenant != "" {
		claims["tenant_id"] = tenant
	}
	if authTime != 0 {
		claims["auth_time"] = float64(authTime)
	}
	claimsStruct, err := structpb.NewStruct(claims)
	require.NoError(t, err)

	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			MetadataContext: &corev3.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					"envoy.filters.http.jwt_authn": {
						Fields: map[string]*structpb.Value{
							"trial": structpb.NewStructValue(claimsStruct),
						},
					},
				},
			},
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: method,
					Path:   path,
				},
			},
			ContextExtensions: ext,
		},
	}
}

func doCheck(t *testing.T, req *authv3.CheckRequest) *authv3.CheckResponse {
	t.Helper()
	resp, err := grpcClient.Check(checkContext(t), req)
	require.NoError(t, err, "Check RPC itself must not error — a Deny is a normal CheckResponse, not a gRPC error")
	return resp
}

func headerMap(resp *authv3.CheckResponse) map[string]string {
	ok := resp.GetOkResponse()
	if ok == nil {
		return nil
	}
	m := make(map[string]string, len(ok.GetHeaders()))
	for _, h := range ok.GetHeaders() {
		m[h.GetHeader().GetKey()] = h.GetHeader().GetValue()
	}
	return m
}

func denyReason(resp *authv3.CheckResponse) string {
	return resp.GetStatus().GetMessage()
}

// TestGoldenPath_Allow proves the full read-through rebuild path — cache
// miss, real I-8 call to the fake Org & Membership server, cache
// populated, six-header Allow response — matches what README.md's "Seeing
// an Allow decision" walkthrough demonstrates by hand.
func TestGoldenPath_Allow(t *testing.T) {
	tenant, user := id("tenant-e2e-golden"), "golden-user"
	org.setMembership(tenant, user, membershipFixture{
		Roles:              []string{"tenant_admin"},
		Departments:        []departmentFixture{{DepartmentID: "dept-1", Level: "reviewer"}},
		Plan:               "pro",
		FeatureFlags:       []string{"flag-a"},
		SubscriptionStatus: "active",
		ReadOnly:           false,
	})

	resp := doCheck(t, buildCheckRequest(t, user, tenant, 0, "GET", "/api/v1/tenders", nil))

	require.NotNil(t, resp.GetOkResponse(), "expected Allow, got deny reason %q", denyReason(resp))
	headers := headerMap(resp)
	require.Equal(t, tenant, headers["x-tenant-id"])
	require.Equal(t, user, headers["x-user-id"])
	require.Equal(t, "dept-1:reviewer", headers["x-departments"])
	require.Equal(t, "tenant_admin", headers["x-tenant-roles"])
	require.Equal(t, "pro", headers["x-plan"])
	require.Equal(t, "flag-a", headers["x-feature-flags"])
}

// TestUnresolvableSubject_Deny proves the §3.1 step-1 subject-resolution
// gate: a subject with no registered membership anywhere gets I-8's 404
// translated into DENY_UNRESOLVABLE_SUBJECT, never a 5xx or an Allow.
func TestUnresolvableSubject_Deny(t *testing.T) {
	resp := doCheck(t, buildCheckRequest(t, "ghost-user", id("tenant-e2e-golden-unresolvable"), 0, "GET", "/api/v1/tenders", nil))

	require.Nil(t, resp.GetOkResponse())
	require.Equal(t, "DENY_UNRESOLVABLE_SUBJECT", denyReason(resp))
}

// TestReadOnlyTenant_DeniesWrite proves policy 6 — a blanket tenant-level
// gate that runs before any role/department check (§4.4 step 2).
func TestReadOnlyTenant_DeniesWrite(t *testing.T) {
	tenant, user := id("tenant-e2e-readonly"), "readonly-user"
	org.setMembership(tenant, user, membershipFixture{
		Roles:    []string{"tenant_admin"},
		ReadOnly: true,
	})

	resp := doCheck(t, buildCheckRequest(t, user, tenant, 0, "POST", "/api/v1/tenders", nil))

	require.Nil(t, resp.GetOkResponse())
	require.Equal(t, "DENY_TENANT_READ_ONLY", denyReason(resp))
}

// TestRoleInsufficient_ThenEventDrivenGrant_Allows proves both policy 3
// (base role check) and the event-driven cache-invalidation loop end to
// end: a real DepartmentMembershipGranted message, delivered over real
// SQS, actually evicts ae:ctx and the next Check() rebuilds from the
// (now-updated) fake Org & Membership response — the one behavior no unit
// test can observe, since unit tests call Invalidator directly rather than
// going through the real queue.
func TestRoleInsufficient_ThenEventDrivenGrant_Allows(t *testing.T) {
	tenant, user := id("tenant-e2e-cache"), "cache-evict-user"
	org.setMembership(tenant, user, membershipFixture{Roles: []string{"viewer"}})

	req := buildCheckRequest(t, user, tenant, 0, "POST", "/api/v1/departments/memberships",
		map[string]string{"policy_action": "manage_department_memberships"})

	resp := doCheck(t, req)
	require.Nil(t, resp.GetOkResponse(), "a viewer must not be allowed to manage department memberships")
	require.Equal(t, "DENY_ROLE_INSUFFICIENT", denyReason(resp))

	// Grant tenant_admin in the fake upstream, then tell this service via
	// the real event bus — not by calling Invalidator directly.
	org.setMembership(tenant, user, membershipFixture{Roles: []string{"tenant_admin"}})
	sendEvent(t, "membership-authz-q", "DepartmentMembershipGranted", tenant, map[string]string{"user_id": user})

	// Allow 2 seconds for the membership-authz-q consumer to complete its
	// current LocalStack poll and start a new one that finds the event.
	// LocalStack v4.4.0 may not wake up mid-poll when a new message arrives
	// (even with WaitTimeSeconds=1), so a short sleep ensures the next poll
	// starts fresh after the event is already in the queue.
	time.Sleep(2 * time.Second)

	eventually(t, 25*time.Second, func() bool {
		return doCheck(t, req).GetOkResponse() != nil
	})
}

// TestMFAFreshness_FreshAllowsStaleDenies proves §3.1 step 5 / §4.4's
// never-cached MFA-freshness gate — same recipe as README.md's "Testing
// the MFA-freshness gate" walkthrough.
func TestMFAFreshness_FreshAllowsStaleDenies(t *testing.T) {
	tenant, user := id("tenant-e2e-mfa"), "mfa-user"
	org.setMembership(tenant, user, membershipFixture{Roles: []string{"tenant_admin"}})
	org.setMFAFreshness(tenant, 300)

	ext := map[string]string{"required_department_level": "approver"}

	fresh := doCheck(t, buildCheckRequest(t, user, tenant, time.Now().Unix(), "POST", "/api/v1/approve", ext))
	require.NotNil(t, fresh.GetOkResponse(), "expected Allow with a fresh auth_time, got deny reason %q", denyReason(fresh))

	stale := doCheck(t, buildCheckRequest(t, user, tenant, time.Now().Add(-10*time.Minute).Unix(), "POST", "/api/v1/approve", ext))
	require.Nil(t, stale.GetOkResponse())
	require.Equal(t, "DENY_MFA_STALE", denyReason(stale))
}

// TestTenderACLOverlay_FullFlow proves §3.1 step 4 / §4.2 policy 8 across
// all three states: skipped while unrestricted, enforced (and denying) once
// a real TenderRestricted event arrives, and enforced-and-allowing for a
// sufficient TAC-4 grant — same recipe as README.md's "Testing the
// tender-ACL overlay" walkthrough, but with the restriction event sent over
// real SQS instead of by hand.
func TestTenderACLOverlay_FullFlow(t *testing.T) {
	tenant := id("tenant-e2e-tender")
	org.setMembership(tenant, "unrestricted-user", membershipFixture{Roles: []string{"tenant_admin"}})
	org.setMembership(tenant, "insufficient-user", membershipFixture{Roles: []string{"tenant_admin"}})
	org.setMembership(tenant, "sufficient-user", membershipFixture{Roles: []string{"tenant_admin"}})

	ext := map[string]string{"required_access_level": "view"}

	// 1. Not (yet) restricted: the overlay is skipped entirely, so even a
	// tender with no ACL grant at all still Allows.
	const unrestrictedTender = "tender-e2e-unrestricted"
	req := buildCheckRequest(t, "unrestricted-user", tenant, 0, "GET", "/api/v1/tenders/"+unrestrictedTender, ext)
	resp := doCheck(t, req)
	require.NotNil(t, resp.GetOkResponse(), "overlay must be skipped for a tender never flagged restricted, got deny reason %q", denyReason(resp))

	// 2. Flag a different tender restricted via a real TenderRestricted
	// event, with an insufficient grant already on file — poll until the
	// overlay starts enforcing (proves the event was actually consumed,
	// not just that Deny happened to be the answer already).
	const restrictedTender = "tender-e2e-restricted"
	org.setTenderACL(tenant, restrictedTender, "insufficient-user", tenderACLFixture{HasAccess: false})
	org.setTenderACL(tenant, restrictedTender, "sufficient-user", tenderACLFixture{HasAccess: true, AccessLevel: "approve"})

	insufficientReq := buildCheckRequest(t, "insufficient-user", tenant, 0, "GET", "/api/v1/tenders/"+restrictedTender, ext)
	preRestrict := doCheck(t, insufficientReq)
	require.NotNil(t, preRestrict.GetOkResponse(), "sanity check: must still Allow before the restriction event lands")

	sendEvent(t, "tender-authz-q", "TenderRestricted", tenant, map[string]string{"tender_id": restrictedTender})

	eventually(t, 15*time.Second, func() bool {
		r := doCheck(t, insufficientReq)
		return r.GetOkResponse() == nil && denyReason(r) == "DENY_TENDER_ACL_INSUFFICIENT"
	})

	// 3. A second, distinct user against the SAME (now-confirmed-restricted)
	// tender, with a sufficient grant and a fresh ae:tender_acl cache key —
	// proves the overlay actually consults TAC-4's access_level rather than
	// denying unconditionally once restricted.
	sufficientReq := buildCheckRequest(t, "sufficient-user", tenant, 0, "GET", "/api/v1/tenders/"+restrictedTender, ext)
	sufficient := doCheck(t, sufficientReq)
	require.NotNil(t, sufficient.GetOkResponse(), "expected Allow for a sufficient TAC-4 grant, got deny reason %q", denyReason(sufficient))
}

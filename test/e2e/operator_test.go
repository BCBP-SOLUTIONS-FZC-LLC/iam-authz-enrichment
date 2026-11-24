//go:build e2e

package e2e

import (
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// CD-52 operator path (LLD §8.9), through the real binary: OPERATOR_REALM_ISSUER
// from env, realm_access.roles decoded from jwt_authn metadata, the seven
// trusted headers on the wire.

const (
	e2eOperatorSub    = "5d2c8a1e-7b34-4f9a-a0c6-1e8f3b7d9a42"
	e2eOperatorTenant = "9a4e1c7b-2d58-4b3f-8e60-3c1f7a9d2b15"
)

func buildOperatorRequest(t *testing.T, method, path string, roles ...any) *authv3.CheckRequest {
	t.Helper()
	claims, err := structpb.NewStruct(map[string]any{
		"sub":          e2eOperatorSub,
		"iss":          e2eOperatorIssuer,
		"realm_access": map[string]any{"roles": roles},
	})
	require.NoError(t, err)
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			MetadataContext: &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{
				"envoy.filters.http.jwt_authn": {Fields: map[string]*structpb.Value{"trial": structpb.NewStructValue(claims)}},
			}},
			Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{Method: method, Path: path}},
		},
	}
}

func TestOperator_TenantRoute_AllowsWithOperatorHeaders(t *testing.T) {
	resp := doCheck(t, buildOperatorRequest(t, "PUT", "/api/v1/operator/tenants/"+e2eOperatorTenant+"/trial-profile", "platform_operator"))

	require.NotNil(t, resp.GetOkResponse(), "expected Allow, got %q", denyReason(resp))
	h := headerMap(resp)
	require.Equal(t, e2eOperatorTenant, h["x-tenant-id"])
	require.Equal(t, e2eOperatorSub, h["x-user-id"])
	require.Equal(t, "platform_operator", h["x-tenant-roles"])
	for _, k := range []string{"x-departments", "x-plan", "x-feature-flags", "x-residency-mode"} {
		v, present := h[k]
		require.True(t, present, "%s must be sent (empty) to overwrite any client copy", k)
		require.Empty(t, v, k)
	}
}

func TestOperator_NonTenantRoute_GetsNilTenant(t *testing.T) {
	resp := doCheck(t, buildOperatorRequest(t, "POST", "/api/v1/operator/billing/reconciliation-runs", "platform_operator"))

	require.NotNil(t, resp.GetOkResponse(), "expected Allow, got %q", denyReason(resp))
	require.Equal(t, "00000000-0000-0000-0000-000000000000", headerMap(resp)["x-tenant-id"])
}

// A-10 (a) BL-OQ-26: all platform-realm roles forwarded in x-tenant-roles so
// Billing can gate on pci_owner_reviewer without AuthZ knowing the role name.
func TestOperator_MultiRoleForwarded(t *testing.T) {
	const certID = "d3e5f7a9-2b4c-6d8e-0f1a-3b5c7d9e1f2a"
	resp := doCheck(t, buildOperatorRequest(t, "POST",
		"/api/v1/operator/billing/provider-certifications/"+certID+"/review",
		"platform_operator", "pci_owner_reviewer"))

	require.NotNil(t, resp.GetOkResponse(), "expected Allow, got %q", denyReason(resp))
	require.Equal(t, "platform_operator,pci_owner_reviewer", headerMap(resp)["x-tenant-roles"])
	require.Equal(t, "00000000-0000-0000-0000-000000000000", headerMap(resp)["x-tenant-id"])
}

// A-10 (b) BL-OQ-26 / B-O17: POST /api/v1/operator/billing/provider-certifications/:id/review
// No tenant UUID in path → x-tenant-id = nil UUID; Billing gates on pci_owner_reviewer itself.
func TestOperator_ProviderCertificationReview_AllowAndDeny(t *testing.T) {
	const certID = "d3e5f7a9-2b4c-6d8e-0f1a-3b5c7d9e1f2a"
	path := "/api/v1/operator/billing/provider-certifications/" + certID + "/review"

	resp := doCheck(t, buildOperatorRequest(t, "POST", path, "platform_operator", "pci_owner_reviewer"))
	require.NotNil(t, resp.GetOkResponse(), "expected Allow, got %q", denyReason(resp))
	require.Equal(t, "00000000-0000-0000-0000-000000000000", headerMap(resp)["x-tenant-id"])

	resp = doCheck(t, buildOperatorRequest(t, "POST", path))
	require.Nil(t, resp.GetOkResponse(), "no platform_operator must be denied")
	require.Equal(t, "DENY_ROLE_INSUFFICIENT", denyReason(resp))
}

// A-9 (a) BL-OQ-25 / B-O16: POST /api/v1/operator/tenants/:id/invoices/:invoice_id/disposition
func TestOperator_InvoiceDisposition_AllowAndDeny(t *testing.T) {
	const invoiceID = "c2d4e6f8-1a3b-4c5d-9e0f-2a4b6c8d0e1f"
	path := "/api/v1/operator/tenants/" + e2eOperatorTenant + "/invoices/" + invoiceID + "/disposition"

	resp := doCheck(t, buildOperatorRequest(t, "POST", path, "platform_operator"))
	require.NotNil(t, resp.GetOkResponse(), "expected Allow, got %q", denyReason(resp))
	require.Equal(t, e2eOperatorTenant, headerMap(resp)["x-tenant-id"])

	resp = doCheck(t, buildOperatorRequest(t, "POST", path))
	require.Nil(t, resp.GetOkResponse(), "no platform_operator role must be denied")
	require.Equal(t, "DENY_ROLE_INSUFFICIENT", denyReason(resp))

	resp = doCheck(t, buildOperatorRequest(t, "POST",
		"/api/v1/operator/tenants/not-a-uuid/invoices/"+invoiceID+"/disposition", "platform_operator"))
	require.Nil(t, resp.GetOkResponse(), "malformed tenant UUID must be denied")
	require.Equal(t, "DENY_MALFORMED_IDENTITY", denyReason(resp))
}

func TestOperator_Denials(t *testing.T) {
	cases := map[string]struct {
		req    *authv3.CheckRequest
		reason string
	}{
		"tenant_route":    {buildOperatorRequest(t, "GET", "/api/v1/tenants/"+e2eOperatorTenant+"/members", "platform_operator"), "DENY_ROLE_INSUFFICIENT"},
		"no_role":         {buildOperatorRequest(t, "GET", "/api/v1/operator/tenants/"+e2eOperatorTenant+"/entitlements"), "DENY_ROLE_INSUFFICIENT"},
		"staff_role_only": {buildOperatorRequest(t, "PUT", "/api/v1/operator/tenants/"+e2eOperatorTenant+"/trial-profile", "commercial_trial_manager"), "DENY_ROLE_INSUFFICIENT"},
		"bad_tenant":      {buildOperatorRequest(t, "GET", "/api/v1/operator/tenants/acme/entitlements", "platform_operator"), "DENY_MALFORMED_IDENTITY"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			resp := doCheck(t, c.req)
			require.Nil(t, resp.GetOkResponse())
			require.Equal(t, c.reason, denyReason(resp))
		})
	}
}

// OP-G4 coverage for Commercial Billing's operator routes B-O1..B-O15 (Billing
// LLD §5.3, BL-OQ-9), through the real binary. No route list exists in this
// service: the whole /api/v1/operator/ prefix is admitted, so this pins that
// each Billing path is allowed with the right x-tenant-id.
func TestOperator_BillingRoutes(t *testing.T) {
	const runID = "0193a8f0-1c2d-7e3f-9a4b-5c6d7e8f9a0b"
	routes := []struct {
		id, method, path string
		tenantInPath     bool
	}{
		{"B-O1", "POST", "/api/v1/operator/tenants/" + e2eOperatorTenant + "/conversions", true},
		{"B-O2", "POST", "/api/v1/operator/tenants/" + e2eOperatorTenant + "/adjustments", true},
		{"B-O3", "POST", "/api/v1/operator/tenants/" + e2eOperatorTenant + "/refunds", true},
		{"B-O4", "GET", "/api/v1/operator/tenants/" + e2eOperatorTenant + "/invoices", true},
		{"B-O5", "POST", "/api/v1/operator/billing/reconciliation-runs", false},
		{"B-O6", "GET", "/api/v1/operator/billing/reconciliation-runs/" + runID, false},
		{"B-O7", "GET", "/api/v1/operator/tenants/" + e2eOperatorTenant + "/subscription", true},
		{"B-O8", "POST", "/api/v1/operator/tenants/" + e2eOperatorTenant + "/conversion-reversals", true},
		{"B-O9", "POST", "/api/v1/operator/tenants/" + e2eOperatorTenant + "/conversion-sagas/" + runID + "/actions", true},
		{"B-O10", "PUT", "/api/v1/operator/tenants/" + e2eOperatorTenant + "/collection-pause", true},
		{"B-O11", "POST", "/api/v1/operator/billing/plan-prices", false},
		{"B-O12", "POST", "/api/v1/operator/billing/token-packs", false},
		{"B-O13", "POST", "/api/v1/operator/billing/webhook-events/stripe/evt_1QabcDEF/replay", false},
		{"B-O14", "POST", "/api/v1/operator/billing/provider-certifications", false},
		{"B-O15", "POST", "/api/v1/operator/billing/provider-certifications/" + runID + "/revoke", false},
	}
	for _, r := range routes {
		t.Run(r.id, func(t *testing.T) {
			resp := doCheck(t, buildOperatorRequest(t, r.method, r.path, "platform_operator"))
			require.NotNil(t, resp.GetOkResponse(), "expected Allow, got %q", denyReason(resp))
			want := "00000000-0000-0000-0000-000000000000"
			if r.tenantInPath {
				want = e2eOperatorTenant
			}
			h := headerMap(resp)
			require.Equal(t, want, h["x-tenant-id"])
			require.Equal(t, "platform_operator", h["x-tenant-roles"])

			denied := doCheck(t, buildOperatorRequest(t, r.method, r.path))
			require.Nil(t, denied.GetOkResponse())
			require.Equal(t, "DENY_ROLE_INSUFFICIENT", denyReason(denied))
		})
	}
}

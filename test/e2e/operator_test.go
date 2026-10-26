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

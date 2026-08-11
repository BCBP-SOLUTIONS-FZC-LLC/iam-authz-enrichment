package grpc_test

import (
	"context"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	grpcadapter "github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/inbound/grpc"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/test/fixtures"
)

const (
	jwtNamespace = "envoy.filters.http.jwt_authn"
	jwtPayload   = "trial"
	testIssuer   = "https://kc.example.com/realms/acme"
	testTenant   = "tenant-acme"
	testUser     = "alice"
)

func newTestServer(t *testing.T) *grpcadapter.Server {
	t.Helper()
	cache := fixtures.NewFakeCache()
	cache.SeedMembershipContext(testTenant, testUser, domain.MembershipContext{
		Roles:       []string{"tenant_admin"},
		Departments: []domain.Department{{DepartmentID: "eng", Level: "reviewer"}},
	}, domain.CacheFresh)
	cache.SeedTenantContext(testTenant, domain.TenantContext{Plan: "pro", FeatureFlags: []string{"flag-a"}}, domain.CacheFresh)

	realmMap := usecase.NewRealmMap(map[string]string{testIssuer: testTenant})
	checker := usecase.NewChecker(cache, &fixtures.FakeOrgMembershipClient{}, realmMap, usecase.NewRestrictedTenderSet(),
		fixtures.NoopLogger{}, usecase.NoopRecorder{}, usecase.CheckerConfig{})

	return grpcadapter.NewServer(checker, grpcadapter.JWTMetadata{Namespace: jwtNamespace, PayloadKey: jwtPayload})
}

// buildCheckRequest constructs a CheckRequest with verified-JWT dynamic
// metadata (the only legitimate identity input) plus optional raw HTTP
// request headers, which a real Envoy would never populate with these
// specific names but a compromised/misconfigured upstream might attempt to
// smuggle in anyway.
func buildCheckRequest(t *testing.T, spoofedHeaders map[string]string) *authv3.CheckRequest {
	t.Helper()
	claims, err := structpb.NewStruct(map[string]interface{}{
		"sub": testUser,
		"iss": testIssuer,
	})
	require.NoError(t, err)

	filterMeta, err := structpb.NewStruct(nil)
	require.NoError(t, err)
	filterMeta.Fields[jwtPayload] = structpb.NewStructValue(claims)

	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			MetadataContext: &corev3.Metadata{
				FilterMetadata: map[string]*structpb.Struct{jwtNamespace: filterMeta},
			},
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  "GET",
					Path:    "/api/v1/tenders/1",
					Headers: spoofedHeaders,
				},
			},
			ContextExtensions: map[string]string{},
		},
	}
}

func TestServer_Check_Allows(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)

	resp, err := server.Check(context.Background(), buildCheckRequest(t, nil))

	require.NoError(t, err)
	okResp := resp.GetOkResponse()
	require.NotNil(t, okResp)
	found := map[string]string{}
	for _, h := range okResp.GetHeaders() {
		found[h.GetHeader().GetKey()] = h.GetHeader().GetValue()
	}
	assert.Equal(t, testTenant, found[domain.HeaderTenantID])
	assert.Equal(t, testUser, found[domain.HeaderUserID])
}

// The §8.2 regression test: a CheckRequest with spoofed inbound headers that
// disagree with the verified JWT must produce a byte-identical decision and
// output headers to the same request without those headers — proving this
// service never reads req.Attributes.Request.Http.Headers for identity or
// policy facts.
func TestServer_Check_IgnoresSpoofedInboundHeaders(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)

	clean, err := server.Check(context.Background(), buildCheckRequest(t, nil))
	require.NoError(t, err)

	spoofed, err := server.Check(context.Background(), buildCheckRequest(t, map[string]string{
		domain.HeaderTenantID:     "evil-tenant",
		domain.HeaderUserID:       "evil-user",
		domain.HeaderDepartments:  "evil-dept:approver",
		domain.HeaderTenantRoles:  "tenant_owner",
		domain.HeaderPlan:         "enterprise",
		domain.HeaderFeatureFlags: "all-the-flags",
		"authorization":           "Bearer forged-token",
	}))
	require.NoError(t, err)

	assert.True(t, proto.Equal(clean, spoofed), "spoofed inbound headers must never change the decision or output headers")
}

func TestServer_Check_DeniesViaChecker(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)

	claims, err := structpb.NewStruct(map[string]interface{}{
		"sub": testUser, "iss": "https://issuer/unknown-realm",
	})
	require.NoError(t, err)
	filterMeta, err := structpb.NewStruct(nil)
	require.NoError(t, err)
	filterMeta.Fields[jwtPayload] = structpb.NewStructValue(claims)

	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			MetadataContext: &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{jwtNamespace: filterMeta}},
			Request:         &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{Method: "GET"}},
		},
	}

	resp, err := server.Check(context.Background(), req)

	require.NoError(t, err)
	denied := resp.GetDeniedResponse()
	require.NotNil(t, denied, "an unresolvable issuer must deny through the checker, not just the pre-checker subject guard")
	assert.Equal(t, string(domain.DenyMalformedIdentity), denied.GetBody())
}

func TestServer_Check_MissingSubject_DeniesMalformedIdentity(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)

	req := &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{Method: "GET"}},
	}}

	resp, err := server.Check(context.Background(), req)

	require.NoError(t, err)
	denied := resp.GetDeniedResponse()
	require.NotNil(t, denied)
	assert.EqualValues(t, 401, denied.GetStatus().GetCode())
}

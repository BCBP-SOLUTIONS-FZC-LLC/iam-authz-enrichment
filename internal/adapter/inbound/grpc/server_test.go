package grpc_test

import (
	"context"
	"net"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

// TC-046: a nil CheckRequest must not panic — the gRPC framework guarantees
// non-nil in production, but a fuzzer or buggy client could send nil.
// The proto GetX() accessors are nil-safe, so the request decodes to zero
// claims → subject is empty → DENY_MALFORMED_IDENTITY, no panic.
func TestServer_Check_NilRequest_DoesNotPanic(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)

	var resp *authv3.CheckResponse
	var err error
	assert.NotPanics(t, func() {
		resp, err = server.Check(context.Background(), nil)
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	denied := resp.GetDeniedResponse()
	require.NotNil(t, denied, "nil request must produce a Deny, not Allow")
	assert.EqualValues(t, 401, denied.GetStatus().GetCode(), "nil request → no subject → DENY_MALFORMED_IDENTITY (401)")
}

// TC-061: an in-flight Check must complete before GracefulStop returns.
// GracefulStop stops accepting new RPCs but waits for active ones to finish —
// this test verifies the guarantee holds when a Check is stalled mid-handler
// (e.g. waiting on a slow org-membership sibling response).
func TestServer_GracefulStop_InFlightCheckCompletes(t *testing.T) {
	t.Parallel()

	handlerStarted := make(chan struct{})
	block := make(chan struct{})
	slowOrg := &fixtures.FakeOrgMembershipClient{
		GetMembershipsFunc: func(_ context.Context, _, _ string) (domain.MembershipContext, domain.TenantContext, error) {
			close(handlerStarted) // signals the test that we're blocked inside the handler
			<-block
			return domain.NewMembershipContext(), domain.NewTenantContext(), nil
		},
	}

	realmMap := usecase.NewRealmMap(map[string]string{testIssuer: testTenant})
	checker := usecase.NewChecker(
		fixtures.NewFakeCache(), slowOrg, realmMap, usecase.NewRestrictedTenderSet(),
		fixtures.NoopLogger{}, usecase.NoopRecorder{}, usecase.CheckerConfig{},
	)

	srv := grpc.NewServer()
	authv3.RegisterAuthorizationServer(srv, grpcadapter.NewServer(checker, grpcadapter.JWTMetadata{
		Namespace: jwtNamespace, PayloadKey: jwtPayload,
	}))
	var lc net.ListenConfig
	lis, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(lis) }()

	conn, dialErr := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, dialErr)
	t.Cleanup(func() { _ = conn.Close() })

	type result struct {
		resp *authv3.CheckResponse
		err  error
	}
	checkDone := make(chan result, 1)
	go func() {
		resp, callErr := authv3.NewAuthorizationClient(conn).Check(context.Background(), buildCheckRequest(t, nil))
		checkDone <- result{resp: resp, err: callErr}
	}()

	// Wait until the handler goroutine is confirmed to be blocked inside the
	// slow org call, then trigger GracefulStop.
	select {
	case <-handlerStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("handler goroutine did not start within 5s")
	}

	stopDone := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(stopDone)
	}()

	// Release the blocker so the in-flight Check can complete.
	close(block)

	select {
	case r := <-checkDone:
		require.NoError(t, r.err)
		require.NotNil(t, r.resp)
		assert.NotNil(t, r.resp.GetOkResponse(), "in-flight Check must complete with an Allow after blocker is released")
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight Check did not complete within 5s")
	}

	select {
	case <-stopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("GracefulStop did not return within 5s after the in-flight Check completed")
	}
}

// TC-037: nil ContextExtensions means no route config is attached — the
// gRPC adapter decodes this as ActionGeneric (all ext map lookups return "")
// so the base policy trivially passes and the request is Allowed.
func TestServer_Check_NilContextExtensions_Allows(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)

	claims, err := structpb.NewStruct(map[string]interface{}{"sub": testUser, "iss": testIssuer})
	require.NoError(t, err)
	filterMeta, err := structpb.NewStruct(nil)
	require.NoError(t, err)
	filterMeta.Fields[jwtPayload] = structpb.NewStructValue(claims)

	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			MetadataContext: &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{jwtNamespace: filterMeta}},
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{Method: "GET", Path: "/api/v1/resource"},
			},
			ContextExtensions: nil,
		},
	}

	resp, err := server.Check(context.Background(), req)

	require.NoError(t, err)
	assert.NotNil(t, resp.GetOkResponse(),
		"nil ContextExtensions must not deny — no route config means ActionGeneric, which always passes")
}

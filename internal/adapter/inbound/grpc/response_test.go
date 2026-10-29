package grpc

import (
	"encoding/json"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

func TestHTTPStatusCode(t *testing.T) {
	t.Parallel()
	assert.Equal(t, typev3.StatusCode_Unauthorized, httpStatusCode(401))
	assert.Equal(t, typev3.StatusCode_ServiceUnavailable, httpStatusCode(503))
	assert.Equal(t, typev3.StatusCode_Forbidden, httpStatusCode(403))
	assert.Equal(t, typev3.StatusCode_Forbidden, httpStatusCode(999), "any other status defaults to Forbidden")
}

func TestGRPCCode(t *testing.T) {
	t.Parallel()
	assert.Equal(t, codes.Unauthenticated, grpcCode(401))
	assert.Equal(t, codes.Unavailable, grpcCode(503))
	assert.Equal(t, codes.PermissionDenied, grpcCode(403))
	assert.Equal(t, codes.PermissionDenied, grpcCode(999), "any other status defaults to PermissionDenied")
}

func TestOkResponse_HeadersSortedDeterministically(t *testing.T) {
	t.Parallel()
	resp := okResponse(map[string]string{"z-header": "1", "a-header": "2"})

	ok := resp.GetOkResponse()
	require := assert.New(t)
	require.Len(ok.GetHeaders(), 2)
	require.Equal("a-header", ok.GetHeaders()[0].GetHeader().GetKey())
	require.Equal("z-header", ok.GetHeaders()[1].GetHeader().GetKey())
}

// TestOkResponse_HeadersOverwriteClientCopies pins that every injected header
// replaces a same-named request header rather than being appended next to a
// client-supplied value (HLD §11.1, AE-SEC-1): the action is explicit, and the
// deprecated `append` flag is never set (it would take precedence over it).
func TestOkResponse_HeadersOverwriteClientCopies(t *testing.T) {
	t.Parallel()
	resp := okResponse(map[string]string{domain.HeaderPlan: "pro", domain.HeaderTenantRoles: "member"})

	hdrs := resp.GetOkResponse().GetHeaders()
	assert.Len(t, hdrs, 2)
	for _, h := range hdrs {
		assert.Equal(t, corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD, h.GetAppendAction(), h.GetHeader().GetKey())
		//nolint:staticcheck // reading the deprecated append field is the point: if set it would override AppendAction
		assert.Nil(t, h.GetAppend(), "%s: the deprecated append flag must stay unset", h.GetHeader().GetKey())
	}
}

func denyRequest(path string, headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Request: &authv3.AttributeContext_Request{
			Http: &authv3.AttributeContext_HttpRequest{Path: path, Headers: headers},
		},
	}}
}

func TestDeniedResponse_ReasonStaysOnGRPCMessage(t *testing.T) {
	t.Parallel()
	resp := deniedResponse(domain.DenyMFAStale, denyRequest("/api/v1/x", nil), "")
	assert.Equal(t, string(domain.DenyMFAStale), resp.GetStatus().GetMessage(),
		"Envoy's access log keeps the bare reason")
}

// AE-42 / CD-31: every deny body is an RFC 9457 problem with the platform
// type for its status and errorCode = the DENY_* reason.
func TestDeniedResponse_ProblemJSONBody(t *testing.T) {
	t.Parallel()
	cases := []struct {
		reason domain.DenyReason
		status int
		typ    string
		title  string
	}{
		{domain.DenyMalformedIdentity, 401, "https://errors.company.com/platform/unauthorized", "Unauthorized"},
		{domain.DenyUnresolvableSubject, 403, "https://errors.company.com/platform/forbidden", "Forbidden"},
		{domain.DenyTenantReadOnly, 403, "https://errors.company.com/platform/forbidden", "Forbidden"},
		{domain.DenyMFAStale, 403, "https://errors.company.com/platform/forbidden", "Forbidden"},
		{domain.DenyTenderACLInsufficient, 403, "https://errors.company.com/platform/forbidden", "Forbidden"},
		{domain.DenyRoleInsufficient, 403, "https://errors.company.com/platform/forbidden", "Forbidden"},
		{domain.DenyServiceUnavailable, 503, "https://errors.company.com/platform/service-unavailable", "Service Unavailable"},
	}
	const tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	for _, tc := range cases {
		t.Run(string(tc.reason), func(t *testing.T) {
			t.Parallel()
			resp := deniedResponse(tc.reason, denyRequest("/api/v1/tenders/42?draft=1", map[string]string{"traceparent": tp}), "")
			denied := resp.GetDeniedResponse()

			require.Len(t, denied.GetHeaders(), 1)
			assert.Equal(t, "content-type", denied.GetHeaders()[0].GetHeader().GetKey())
			assert.Equal(t, "application/problem+json", denied.GetHeaders()[0].GetHeader().GetValue())

			var body map[string]any
			require.NoError(t, json.Unmarshal([]byte(denied.GetBody()), &body), denied.GetBody())
			assert.Equal(t, tc.typ, body["type"])
			assert.Equal(t, tc.title, body["title"])
			assert.EqualValues(t, tc.status, body["status"])
			assert.Equal(t, string(tc.reason), body["errorCode"])
			assert.Equal(t, denyDetails[tc.reason], body["detail"])
			assert.NotEmpty(t, body["detail"], "every reason has a fixed detail")
			assert.Equal(t, "/api/v1/tenders/42", body["instance"], "path without the query string")
			assert.Equal(t, "0af7651916cd43dd8448eb211c80319c", body["traceId"])
			assert.NotEmpty(t, body["timestamp"])
			assert.ElementsMatch(t,
				[]string{"type", "title", "status", "detail", "instance", "traceId", "errorCode", "timestamp"},
				keys(body), "no other members (no tenantId, no internal detail)")
			assert.EqualValues(t, tc.status, int(denied.GetStatus().GetCode()))
		})
	}
}

func TestDeniedResponse_TraceIDFallbacks(t *testing.T) {
	t.Parallel()
	body := func(h map[string]string, span string) map[string]any {
		var b map[string]any
		require.NoError(t, json.Unmarshal([]byte(deniedResponse(domain.DenyRoleInsufficient, denyRequest("/p", h), span).GetDeniedResponse().GetBody()), &b))
		return b
	}
	assert.Equal(t, "req-123", body(map[string]string{"x-request-id": "req-123"}, "")["traceId"])
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", body(nil, "4bf92f3577b34da6a3ce929d0e0e4736")["traceId"])
	assert.Len(t, body(nil, ""), 8, "a generated traceId when nothing is available")
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

package grpc

import (
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/stretchr/testify/assert"
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

func TestDeniedResponse_CarriesReasonAsMessageAndBody(t *testing.T) {
	t.Parallel()
	resp := deniedResponse(domain.DenyMFAStale)

	assert.Equal(t, string(domain.DenyMFAStale), resp.GetStatus().GetMessage())
	assert.Equal(t, string(domain.DenyMFAStale), resp.GetDeniedResponse().GetBody())
}

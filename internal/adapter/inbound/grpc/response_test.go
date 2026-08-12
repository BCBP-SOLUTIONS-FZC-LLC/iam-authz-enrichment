package grpc

import (
	"testing"

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

func TestDeniedResponse_CarriesReasonAsMessageAndBody(t *testing.T) {
	t.Parallel()
	resp := deniedResponse(domain.DenyMFAStale)

	assert.Equal(t, string(domain.DenyMFAStale), resp.GetStatus().GetMessage())
	assert.Equal(t, string(domain.DenyMFAStale), resp.GetDeniedResponse().GetBody())
}

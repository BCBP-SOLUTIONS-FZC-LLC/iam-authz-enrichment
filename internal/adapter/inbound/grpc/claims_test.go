package grpc

import (
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	testNamespace = "envoy.filters.http.jwt_authn"
	testPayload   = "trial"
)

func requestWithClaims(t *testing.T, claims map[string]interface{}) *authv3.CheckRequest {
	t.Helper()
	s, err := structpb.NewStruct(claims)
	require.NoError(t, err)
	filterMeta, err := structpb.NewStruct(nil)
	require.NoError(t, err)
	filterMeta.Fields[testPayload] = structpb.NewStructValue(s)

	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			MetadataContext: &corev3.Metadata{
				FilterMetadata: map[string]*structpb.Struct{testNamespace: filterMeta},
			},
		},
	}
}

func TestDecodeClaims_FullSet(t *testing.T) {
	t.Parallel()
	req := requestWithClaims(t, map[string]interface{}{
		"sub": "alice", "iss": "https://issuer", "tenant_id": "tenant-1", "auth_time": 1700000000.0,
	})

	claims := decodeClaims(req, JWTMetadata{Namespace: testNamespace, PayloadKey: testPayload})

	assert.Equal(t, "alice", claims.Subject)
	assert.Equal(t, "https://issuer", claims.Issuer)
	assert.Equal(t, "tenant-1", claims.TenantID)
	assert.EqualValues(t, 1700000000, claims.AuthTime)
}

func TestDecodeClaims_NoMetadataContext(t *testing.T) {
	t.Parallel()
	claims := decodeClaims(&authv3.CheckRequest{Attributes: &authv3.AttributeContext{}}, JWTMetadata{Namespace: testNamespace, PayloadKey: testPayload})
	assert.Zero(t, claims)
}

func TestDecodeClaims_NamespaceMissing(t *testing.T) {
	t.Parallel()
	req := requestWithClaims(t, map[string]interface{}{"sub": "alice"})
	claims := decodeClaims(req, JWTMetadata{Namespace: "some.other.namespace", PayloadKey: testPayload})
	assert.Zero(t, claims)
}

func TestDecodeClaims_PayloadKeyMissing(t *testing.T) {
	t.Parallel()
	req := requestWithClaims(t, map[string]interface{}{"sub": "alice"})
	claims := decodeClaims(req, JWTMetadata{Namespace: testNamespace, PayloadKey: "wrong-key"})
	assert.Zero(t, claims)
}

func TestDecodeClaims_PayloadNotAStruct(t *testing.T) {
	t.Parallel()
	filterMeta, err := structpb.NewStruct(nil)
	require.NoError(t, err)
	filterMeta.Fields[testPayload] = structpb.NewStringValue("not-a-struct")
	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			MetadataContext: &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{testNamespace: filterMeta}},
		},
	}

	claims := decodeClaims(req, JWTMetadata{Namespace: testNamespace, PayloadKey: testPayload})
	assert.Zero(t, claims)
}

func TestAuthTimeField_NumericValue(t *testing.T) {
	t.Parallel()
	fields := map[string]*structpb.Value{"auth_time": structpb.NewNumberValue(12345)}
	assert.EqualValues(t, 12345, authTimeField(fields))
}

func TestAuthTimeField_StringEncodedValue(t *testing.T) {
	t.Parallel()
	fields := map[string]*structpb.Value{"auth_time": structpb.NewStringValue("12345")}
	assert.EqualValues(t, 12345, authTimeField(fields))
}

func TestAuthTimeField_InvalidStringValue(t *testing.T) {
	t.Parallel()
	fields := map[string]*structpb.Value{"auth_time": structpb.NewStringValue("not-a-number")}
	assert.EqualValues(t, 0, authTimeField(fields))
}

func TestAuthTimeField_MissingKey(t *testing.T) {
	t.Parallel()
	assert.EqualValues(t, 0, authTimeField(map[string]*structpb.Value{}))
}

func TestAuthTimeField_NumberZero_IsDistinctFromAbsent(t *testing.T) {
	t.Parallel()
	// structpb.GetNumberValue() returns 0.0 for both the number zero and for
	// a non-number kind. Checking v.Kind.(*structpb.Value_NumberValue) correctly
	// distinguishes auth_time:0 (a legitimate number) from absent/non-numeric.
	// In practice auth_time=0 (Unix epoch) is not issued by any real IdP, but
	// the code must not conflate it with "claim absent" — the zero-number case
	// must return 0, same as absent, without using GetNumberValue() != 0 check.
	fields := map[string]*structpb.Value{"auth_time": structpb.NewNumberValue(0)}
	assert.EqualValues(t, 0, authTimeField(fields), "auth_time=0 must decode as 0, not be confused with absent")
}

func TestAuthTimeField_NonNumericKind_ReturnsZero(t *testing.T) {
	t.Parallel()
	// A boolean auth_time (malformed JWT) must not be mistakenly read as a
	// number via GetNumberValue() — both return 0.0, so only the Kind check
	// prevents a false positive.
	fields := map[string]*structpb.Value{"auth_time": structpb.NewBoolValue(true)}
	assert.EqualValues(t, 0, authTimeField(fields))
}

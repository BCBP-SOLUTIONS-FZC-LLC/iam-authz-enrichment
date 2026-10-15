package grpc

import (
	"strconv"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
)

// JWTMetadata configures where Envoy's jwt_authn filter deposits verified
// claims. jwt_authn writes the decoded (and, at that point, already fully
// validated — signature/iss/aud/exp) JWT payload into dynamic metadata, not
// a request header; ext_authz surfaces it via
// CheckRequest.Attributes.MetadataContext when configured with
// metadata_context_namespaces including this filter's namespace. This is
// the mechanism that makes §8.1's invariant (trust only Envoy-validated
// claims, never a client-supplied header) actually hold: nothing in this
// package ever reads req.Attributes.Request.Http.Headers for identity.
type JWTMetadata struct {
	// Namespace is the filter metadata key jwt_authn writes under —
	// conventionally "envoy.filters.http.jwt_authn".
	Namespace string
	// PayloadKey is the key within that namespace's Struct holding the
	// decoded JWT payload — the jwt_authn provider name configured with
	// payload_in_metadata.
	PayloadKey string
}

// decodeClaims extracts usecase.Claims from the verified-JWT dynamic
// metadata on req. Fields absent from the payload decode as zero values —
// tenant resolution (usecase.ResolveTenant) is what turns an unusable claim
// set into DENY_MALFORMED_IDENTITY; this function never itself decides an
// authz outcome.
func decodeClaims(req *authv3.CheckRequest, cfg JWTMetadata) usecase.Claims {
	var claims usecase.Claims

	md := req.GetAttributes().GetMetadataContext()
	if md == nil {
		return claims
	}
	ns, ok := md.GetFilterMetadata()[cfg.Namespace]
	if !ok {
		return claims
	}
	payload, ok := ns.GetFields()[cfg.PayloadKey]
	if !ok {
		return claims
	}
	fields := payload.GetStructValue().GetFields()
	if fields == nil {
		return claims
	}

	claims.Subject = stringField(fields, "sub")
	claims.Issuer = stringField(fields, "iss")
	claims.TenantID = stringField(fields, "tenant_id")
	claims.AuthTime = authTimeField(fields)
	return claims
}

func stringField(fields map[string]*structpb.Value, key string) string {
	v, ok := fields[key]
	if !ok {
		return ""
	}
	return v.GetStringValue()
}

// authTimeField reads the "auth_time" claim, which may arrive as a JSON
// number or, from some IdP/metadata pipelines, a numeric string.
// The Kind check distinguishes auth_time=0 (the number zero, a legitimate
// but unlikely value) from an absent or non-numeric claim — structpb's
// GetNumberValue() returns 0.0 for both, so inspecting the value alone
// cannot distinguish them.
func authTimeField(fields map[string]*structpb.Value) int64 {
	v, ok := fields["auth_time"]
	if !ok {
		return 0
	}
	if _, isNum := v.Kind.(*structpb.Value_NumberValue); isNum {
		return int64(v.GetNumberValue())
	}
	if s := v.GetStringValue(); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

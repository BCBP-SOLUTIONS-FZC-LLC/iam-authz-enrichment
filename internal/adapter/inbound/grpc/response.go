package grpc

import (
	"sort"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// okResponse builds an Allow CheckResponse carrying exactly the six
// InjectedHeaders values from headers — nothing else. Headers is always
// server-computed (domain.Decision.Headers, built from cached
// membership/tenant facts, never from the inbound request) — this is what
// makes the §8.2 header-spoofing invariant hold structurally, not just by
// convention. Keys are sorted so the same Decision always serializes
// identically — map iteration order is otherwise non-deterministic, which
// would make two functionally-identical responses byte-unequal.
func okResponse(headers map[string]string) *authv3.CheckResponse {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	opts := make([]*corev3.HeaderValueOption, 0, len(headers))
	for _, k := range keys {
		opts = append(opts, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{Key: k, Value: headers[k]},
		})
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{Headers: opts},
		},
	}
}

// httpStatusCode maps a Go net/http-style status int to the envoy.type.v3
// enum DeniedHttpResponse needs.
func httpStatusCode(status int) typev3.StatusCode {
	switch status {
	case 401:
		return typev3.StatusCode_Unauthorized
	case 503:
		return typev3.StatusCode_ServiceUnavailable
	default:
		return typev3.StatusCode_Forbidden
	}
}

// grpcCode maps the same status to the google.rpc.Code carried on
// CheckResponse.Status — distinct from DeniedHttpResponse.Status, which is
// what Envoy actually surfaces to the downstream HTTP client.
func grpcCode(status int) codes.Code {
	switch status {
	case 401:
		return codes.Unauthenticated
	case 503:
		return codes.Unavailable
	default:
		return codes.PermissionDenied
	}
}

// deniedResponse builds a Deny CheckResponse for reason, mapped to its §9
// HTTP status. DENY_SERVICE_UNAVAILABLE is the one 5xx-class reason —
// callers/operators must be able to tell "not authorized" apart from "the
// authz system itself is degraded".
func deniedResponse(reason domain.DenyReason) *authv3.CheckResponse {
	status := reason.HTTPStatus()
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(grpcCode(status)), Message: string(reason)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: httpStatusCode(status)},
				Body:   string(reason),
			},
		},
	}
}

package grpc

import (
	"encoding/json"
	"sort"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/v2/pkg/problem"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// okResponse builds an Allow CheckResponse carrying the server-computed
// headers — nothing else. Headers is always server-computed
// (domain.Decision.Headers, built from cached membership/tenant facts, never
// from the inbound request) — this is what makes the §8.2 header-spoofing
// invariant hold structurally, not just by convention. Keys are sorted so the
// same Decision always serializes identically — map iteration order is
// otherwise non-deterministic, which would make two functionally-identical
// responses byte-unequal.
//
// Three-layer defence against client header injection (HLD §11.1, AE-SEC-1):
//
//  1. Ingress strip-list removes client copies before ext_authz sees the request.
//  2. OVERWRITE_IF_EXISTS_OR_ADD (below) overwrites any same-named header still
//     present for the seven permanent headers that are always in the response.
//     Envoy's ext_authz defaults `append` to false (overwrite) for
//     OkHttpResponse.headers, but the deprecated `append` field and
//     `append_action` have changed semantics across Envoy releases; stating the
//     action makes the overwrite independent of that default.
//  3. HeadersToRemove (below) explicitly strips conditional headers absent from
//     this decision (currently only x-auth-time / §16 AE-49). OVERWRITE does
//     not fire for headers absent from the response map, so without this layer
//     a client-supplied x-auth-time would pass through to the upstream on any
//     request whose JWT carries no auth_time claim.
func okResponse(headers map[string]string) *authv3.CheckResponse {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	opts := make([]*corev3.HeaderValueOption, 0, len(headers))
	for _, k := range keys {
		opts = append(opts, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: k, Value: headers[k]},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}

	// Conditional headers not present in this decision must be explicitly
	// removed so a client-supplied value cannot pass through to the upstream.
	var toRemove []string
	for _, h := range []string{domain.HeaderAuthTime} {
		if _, present := headers[h]; !present {
			toRemove = append(toRemove, h)
		}
	}

	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers:         opts,
				HeadersToRemove: toRemove,
			},
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

// denyDetails is the fixed, caller-safe detail sentence for each reason. It
// never carries request data or internal causes (which dependency failed,
// which role was missing); those stay in logs and metrics.
var denyDetails = map[domain.DenyReason]string{
	domain.DenyMalformedIdentity:     "The request has no valid identity.",
	domain.DenyUnresolvableSubject:   "The caller is not an active member of this tenant.",
	domain.DenyMemberSuspended:       "The caller's membership in this tenant is suspended.",
	domain.DenyTenantReadOnly:        "The tenant is read-only; changes are not allowed.",
	domain.DenyMFAStale:              "This action needs a recent multi-factor sign-in.",
	domain.DenyTenderACLInsufficient: "The caller does not have the access level this tender requires.",
	domain.DenyRoleInsufficient:      "The caller's role does not allow this action.",
	domain.DenyServiceUnavailable:    "Authorization is temporarily unavailable. Retry later.",
}

// problemType maps a deny status to the platform problem type: 401
// platform/unauthorized, 503 platform/service-unavailable, every other deny
// platform/forbidden (§9).
func problemType(status int) problem.Type {
	switch status {
	case 401:
		return problem.TypeUnauthorized
	case 503:
		return problem.TypeServiceUnavailable
	default:
		return problem.TypeForbidden
	}
}

// deniedResponse builds a Deny CheckResponse for reason, mapped to its §9
// HTTP status. DENY_SERVICE_UNAVAILABLE is the one 5xx-class reason —
// callers/operators must be able to tell "not authorized" apart from "the
// authz system itself is degraded".
//
// The body Envoy returns to the client is an RFC 9457 problem (AE-42,
// CD-31), the same shape and type URIs every platform service uses
// (platform-gincommon pkg/problem): type = the platform type for the status,
// errorCode = the DENY_* reason, instance = the request path without its
// query, traceId from traceparent, else x-request-id, else the active span
// (problem.ResolveTraceID — the order every platform service uses). The gRPC
// Status.Message still carries the bare reason for Envoy's access log.
func deniedResponse(reason domain.DenyReason, req *authv3.CheckRequest, spanTraceID string) *authv3.CheckResponse {
	status := reason.HTTPStatus()
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(grpcCode(status)), Message: string(reason)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: httpStatusCode(status)},
				Headers: []*corev3.HeaderValueOption{{
					Header:       &corev3.HeaderValue{Key: "content-type", Value: problem.ContentType},
					AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
				}},
				Body: denyProblemBody(reason, status, req, spanTraceID),
			},
		},
	}
}

// denyProblemBody renders the RFC 9457 body for a deny.
func denyProblemBody(reason domain.DenyReason, status int, req *authv3.CheckRequest, spanTraceID string) string {
	http := req.GetAttributes().GetRequest().GetHttp()
	path, _, _ := strings.Cut(http.GetPath(), "?")
	h := http.GetHeaders()
	p := problem.NewBuilder(problemType(status)).
		ErrorCode(string(reason)).
		Detail(denyDetails[reason]).
		Instance(path).
		TraceID(problem.ResolveTraceID(h["traceparent"], h["x-request-id"], spanTraceID)).
		Build()
	// Problem.MarshalJSON fails only on an extension value that cannot be
	// encoded; this problem has no extension members, so it cannot fail.
	body, _ := json.Marshal(p)
	return string(body)
}

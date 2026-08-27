package grpc

import (
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain/policy"
)

// Context-extension keys Envoy's route config attaches per route — see the
// package doc on policy.RequestFacts for why this is the right mechanism
// (raw ext_authz carries no route-semantic action information on its own).
// tender_id is deliberately NOT one of these — see tenderIDFromPath's doc
// comment: a per-resource ID can't be a static route-level value the way
// these can.
const (
	extAction                  = "policy_action"
	extAssigneeUserID          = "assignee_user_id"
	extActingDepartmentID      = "department_id"
	extRequiredDepartmentLevel = "required_department_level"
	extRequiredAccessLevel     = "required_access_level"
)

// tendersPathMarker is the path segment preceding a tender's resource ID in
// every tender-scoped route, e.g. "/api/v1/tenders/tender-1" or
// "/api/v1/tenders/tender-1/sections/3" (POST/PATCH/DELETE alike — the ID
// always sits in the URL path, never only in a request body ext_authz
// doesn't see without extra buffering this service's latency budget can't
// afford).
const tendersPathMarker = "/tenders/"

// tenderIDFromPath extracts a tender's resource ID straight from the raw
// HTTP path, instead of trusting a route-level ContextExtensions entry —
// unlike policy_action/required_access_level/etc., a specific tender's ID
// is a per-request, per-resource value, and Envoy's ExtAuthzPerRoute
// context_extensions is a static map<string,string> authored once per
// route at config time; it has no mechanism to template a URL segment into
// itself per request. Returns "" if the path has no /tenders/{id} segment.
func tenderIDFromPath(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	_, rest, found := strings.Cut(path, tendersPathMarker)
	if !found {
		return ""
	}
	rest, _, _ = strings.Cut(rest, "/")
	return rest
}

// decodeRequestFacts builds policy.RequestFacts from the raw HTTP
// method/path plus route-level ContextExtensions. TenderRestricted is left
// false here — the usecase layer fills it in from its own in-process
// RestrictedTenderSet, which this adapter has no access to.
func decodeRequestFacts(req *authv3.CheckRequest) policy.RequestFacts {
	http := req.GetAttributes().GetRequest().GetHttp()
	ext := req.GetAttributes().GetContextExtensions()

	return policy.RequestFacts{
		Method:                  http.GetMethod(),
		Path:                    http.GetPath(),
		Action:                  policy.Action(ext[extAction]),
		AssigneeUserID:          ext[extAssigneeUserID],
		ActingDepartmentID:      ext[extActingDepartmentID],
		RequiredDepartmentLevel: policy.DepartmentLevel(ext[extRequiredDepartmentLevel]),
		TenderID:                tenderIDFromPath(http.GetPath()),
		RequiredAccessLevel:     ext[extRequiredAccessLevel],
	}
}

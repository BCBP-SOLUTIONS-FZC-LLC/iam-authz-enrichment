package grpc

import (
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain/policy"
)

// Context-extension keys Envoy's route config attaches per route — see the
// package doc on policy.RequestFacts for why this is the right mechanism
// (raw ext_authz carries no route-semantic action information on its own).
const (
	extAction                  = "policy_action"
	extAssigneeUserID          = "assignee_user_id"
	extActingDepartmentID      = "department_id"
	extRequiredDepartmentLevel = "required_department_level"
	extTenderID                = "tender_id"
	extRequiredAccessLevel     = "required_access_level"
)

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
		TenderID:                ext[extTenderID],
		RequiredAccessLevel:     ext[extRequiredAccessLevel],
	}
}

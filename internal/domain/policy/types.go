// Package policy implements the concrete policy predicates from LLD §3 as
// plain Go functions — no Rego/OPA, no policy-compilation step, by deliberate
// latency-budget design (§3: "table-driven Go unit tests are the intended
// testing story"). Every function here is pure: no I/O, no cache/network
// calls, so the precedence chain in internal/usecase/check.go can unit-test
// each gate in isolation.
package policy

// Action identifies which of the HLD-seed base policies (§3.1 step 3)
// applies to the request being evaluated, or ActionGeneric if none do.
//
// Envoy's raw ext_authz CheckRequest carries no route-semantic information —
// it only knows method/path/headers. The action (and the resource facts each
// predicate needs, e.g. who the current assignee is) is attached per-route by
// Envoy's HTTP filter config as ContextExtensions — the standard ext_authz
// pattern for passing static, route-level policy metadata that isn't present
// on the wire. This service trusts ContextExtensions exactly as it trusts any
// other Envoy-supplied attribute (§10 invariant AE-SEC-1 applies: it is never
// derived from a client-controllable header).
type Action string

const (
	// ActionGeneric means no named base policy applies — the base
	// role/department check trivially passes (§3.1's final fallback line).
	ActionGeneric Action = ""
	// ActionEditTenderSection: user must be the current ticket assignee for
	// the tender section's workflow node.
	ActionEditTenderSection Action = "edit_tender_section"
	// ActionOverrideWorkflowAssignee: user must hold tender_admin in the tenant.
	ActionOverrideWorkflowAssignee Action = "override_workflow_assignee"
	// ActionManageDepartmentMemberships: user must hold tenant_admin or
	// tenant_owner in the tenant.
	ActionManageDepartmentMemberships Action = "manage_department_memberships"
)

// DepartmentLevel mirrors the parent HLD's three-level department model.
type DepartmentLevel string

const (
	LevelPreparator DepartmentLevel = "preparator"
	LevelReviewer   DepartmentLevel = "reviewer"
	LevelApprover   DepartmentLevel = "approver"
)

// RequestFacts is the per-request policy metadata Envoy attaches via route
// config (ContextExtensions) plus the raw HTTP method/path, decoded once by
// the inbound gRPC adapter and passed down unchanged.
type RequestFacts struct {
	Method string
	Path   string

	Action Action

	// AssigneeUserID is the current ticket assignee for the tender section
	// node being acted on (ActionEditTenderSection).
	AssigneeUserID string

	// ActingDepartmentID is the department the action is scoped to, used to
	// look up the acting user's level in that department.
	ActingDepartmentID string

	// RequiredDepartmentLevel is the department level this action requires
	// on ActingDepartmentID (e.g. "approver" for a final-approval step).
	// Empty means no department-level requirement.
	RequiredDepartmentLevel DepartmentLevel

	// TenderID and RequiredAccessLevel are set when the action is scoped to
	// a tender that may be flagged restricted (§3.1 step 4). RequiredAccessLevel
	// is one of domain.AccessLevelView/Edit/Approve. Unlike the other fields
	// here, TenderID is parsed by the inbound adapter from the request's raw
	// URL path (a per-resource ID can't be a static ContextExtensions value
	// — see grpc.tenderIDFromPath's doc comment).
	TenderID            string
	TenderRestricted    bool
	RequiredAccessLevel string
}

// IsMutation reports whether the HTTP method is a mutation method
// (POST/PUT/PATCH/DELETE). GET/HEAD are never subject to the read-only gate.
func (f RequestFacts) IsMutation() bool {
	switch f.Method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

// RequiresApproverGate reports whether the MFA-freshness gate (§3.1 step 5)
// applies to this request.
func (f RequestFacts) RequiresApproverGate() bool {
	return f.RequiredDepartmentLevel == LevelApprover
}

// RequiresTenderACL reports whether the tender-ACL overlay (§3.1 step 4)
// applies: the action is tender-scoped and the tender is flagged restricted.
func (f RequestFacts) RequiresTenderACL() bool {
	return f.TenderID != "" && f.TenderRestricted
}

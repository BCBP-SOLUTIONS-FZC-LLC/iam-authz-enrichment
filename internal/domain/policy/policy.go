package policy

import "github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"

// Input is everything a base policy predicate needs to decide. It carries no
// behavior of its own — construction and population happen in the usecase
// layer, which is the only layer allowed to talk to caches/sibling services.
type Input struct {
	Subject    string
	Membership domain.MembershipContext
	Request    RequestFacts
}

// hasRole reports whether the subject holds the given tenant-level role.
func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// departmentLevel returns the acting subject's effective level in
// departmentID, folding in active delegations (a delegate acts at the
// delegated level for that department), and whether any membership or
// delegation grants access to it at all.
func departmentLevel(m domain.MembershipContext, departmentID string) (DepartmentLevel, bool) {
	best := DepartmentLevel("")
	found := false
	rank := map[DepartmentLevel]int{LevelPreparator: 1, LevelReviewer: 2, LevelApprover: 3}
	consider := func(level string) {
		l := DepartmentLevel(level)
		if !found || rank[l] > rank[best] {
			best, found = l, true
		}
	}
	for _, d := range m.Departments {
		if d.DepartmentID == departmentID {
			consider(d.Level)
		}
	}
	for _, d := range m.Delegations {
		if d.DepartmentID == departmentID {
			consider(d.Level)
		}
	}
	return best, found
}

// MeetsDepartmentLevel reports whether the subject's effective level in
// departmentID is at least `required`.
func MeetsDepartmentLevel(m domain.MembershipContext, departmentID string, required DepartmentLevel) bool {
	rank := map[DepartmentLevel]int{LevelPreparator: 1, LevelReviewer: 2, LevelApprover: 3}
	level, ok := departmentLevel(m, departmentID)
	if !ok {
		return false
	}
	return rank[level] >= rank[required]
}

// EvaluateBase evaluates the base role/department policy (§3.1 step 3): the
// three HLD-seed predicates keyed by Input.Request.Action, or an
// unconditional Allow for ActionGeneric (the doc's explicit fallback — no
// named base policy restricts requests it doesn't recognize).
func EvaluateBase(in Input) bool {
	switch in.Request.Action {
	case ActionEditTenderSection:
		return in.Request.AssigneeUserID != "" && in.Request.AssigneeUserID == in.Subject
	case ActionOverrideWorkflowAssignee:
		return hasRole(in.Membership.Roles, "tender_admin")
	case ActionManageDepartmentMemberships:
		return hasRole(in.Membership.Roles, "tenant_admin") || hasRole(in.Membership.Roles, "tenant_owner")
	case ActionGeneric:
		return true
	default:
		return true
	}
}

// ViolatesReadOnly reports whether a mutation request against a read-only
// tenant must be denied (§3.1 step 2). Read methods are never affected —
// callers must not call this for GET/HEAD (RequestFacts.IsMutation() gates it).
func ViolatesReadOnly(readOnly bool, mutation bool) bool {
	return readOnly && mutation
}

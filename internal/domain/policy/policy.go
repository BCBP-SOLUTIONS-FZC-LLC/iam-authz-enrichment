package policy

import (
	"strings"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

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
// departmentID, and whether any membership grants access to it at all.
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
		return hasRole(in.Membership.Roles, "tender_admin") ||
			hasRole(in.Membership.Roles, "tenant_admin") ||
			hasRole(in.Membership.Roles, "tenant_owner")
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

// Reactivate route (Billing B-P14), split around the tenant segment.
const (
	reactivatePathPrefix = "/api/v1/tenants/"
	reactivatePathSuffix = "/subscription/reactivate"
)

// ReadOnlyExempt reports whether a mutation is exempt from the read-only gate
// (§3.1 step 2, LLD §8.7, AE-52). Exactly one request is: paying to leave the
// read-only state, Billing's B-P14
// `POST /api/v1/tenants/{tenant}/subscription/reactivate`. Without it a
// cancelled tenant could only come back through support (Billing hand-off
// AZ-1, BL-OQ-30).
//
// The match is exact and fails closed: method POST, the path with any query
// removed, and the path tenant equal to the token's resolved tenant — so a
// read-only tenant can never use the exemption on another tenant's path, and
// a trailing slash, a different case or an encoded variant is not exempt.
// Only the read-only gate is skipped; every later check still runs, and
// Billing still checks its own `subscription.manage` permission, which is what
// limits the route to the owner: AuthZ admits any active member of the tenant.
func ReadOnlyExempt(method, path, tenant string) bool {
	if method != "POST" || tenant == "" {
		return false
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return path == reactivatePathPrefix+tenant+reactivatePathSuffix
}

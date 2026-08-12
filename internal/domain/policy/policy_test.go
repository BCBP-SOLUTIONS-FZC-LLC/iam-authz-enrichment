package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain/policy"
)

func TestEvaluateBase_EditTenderSection(t *testing.T) {
	t.Parallel()
	membership := domain.NewMembershipContext()

	assert.True(t, policy.EvaluateBase(policy.Input{
		Subject:    "alice",
		Membership: membership,
		Request:    policy.RequestFacts{Action: policy.ActionEditTenderSection, AssigneeUserID: "alice"},
	}), "current assignee may edit the section")

	assert.False(t, policy.EvaluateBase(policy.Input{
		Subject:    "alice",
		Membership: membership,
		Request:    policy.RequestFacts{Action: policy.ActionEditTenderSection, AssigneeUserID: "bob"},
	}), "non-assignee may not edit the section")

	assert.False(t, policy.EvaluateBase(policy.Input{
		Subject:    "alice",
		Membership: membership,
		Request:    policy.RequestFacts{Action: policy.ActionEditTenderSection, AssigneeUserID: ""},
	}), "no assignee on record must not default-allow")
}

func TestEvaluateBase_OverrideWorkflowAssignee(t *testing.T) {
	t.Parallel()
	withRole := domain.NewMembershipContext()
	withRole.Roles = []string{"tender_admin"}
	without := domain.NewMembershipContext()
	without.Roles = []string{"tenant_owner"} // a real role, just not the required one

	assert.True(t, policy.EvaluateBase(policy.Input{
		Membership: withRole,
		Request:    policy.RequestFacts{Action: policy.ActionOverrideWorkflowAssignee},
	}))
	assert.False(t, policy.EvaluateBase(policy.Input{
		Membership: without,
		Request:    policy.RequestFacts{Action: policy.ActionOverrideWorkflowAssignee},
	}))
}

func TestEvaluateBase_ManageDepartmentMemberships(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		roles []string
		want  bool
	}{
		{"tenant_admin allowed", []string{"tenant_admin"}, true},
		{"tenant_owner allowed", []string{"tenant_owner"}, true},
		{"tender_admin insufficient", []string{"tender_admin"}, false},
		{"no roles insufficient", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			m := domain.NewMembershipContext()
			m.Roles = c.roles
			got := policy.EvaluateBase(policy.Input{
				Membership: m,
				Request:    policy.RequestFacts{Action: policy.ActionManageDepartmentMemberships},
			})
			assert.Equal(t, c.want, got)
		})
	}
}

func TestEvaluateBase_ActionGeneric_AlwaysAllows(t *testing.T) {
	t.Parallel()
	assert.True(t, policy.EvaluateBase(policy.Input{
		Membership: domain.NewMembershipContext(),
		Request:    policy.RequestFacts{Action: policy.ActionGeneric},
	}))
}

func TestEvaluateBase_UnrecognizedAction_DefaultsToAllow(t *testing.T) {
	t.Parallel()
	assert.True(t, policy.EvaluateBase(policy.Input{
		Membership: domain.NewMembershipContext(),
		Request:    policy.RequestFacts{Action: policy.Action("some_future_action_this_code_does_not_know_about")},
	}), "an action this service doesn't recognize must fall back to the same unconditional allow as ActionGeneric")
}

func TestViolatesReadOnly(t *testing.T) {
	t.Parallel()
	assert.True(t, policy.ViolatesReadOnly(true, true), "mutation against read-only tenant must be denied")
	assert.False(t, policy.ViolatesReadOnly(true, false), "read methods are never affected")
	assert.False(t, policy.ViolatesReadOnly(false, true), "non-read-only tenant is never affected")
	assert.False(t, policy.ViolatesReadOnly(false, false))
}

func TestRequestFacts_IsMutation(t *testing.T) {
	t.Parallel()
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		assert.True(t, policy.RequestFacts{Method: m}.IsMutation(), m)
	}
	for _, m := range []string{"GET", "HEAD"} {
		assert.False(t, policy.RequestFacts{Method: m}.IsMutation(), m)
	}
}

func TestRequestFacts_RequiresApproverGate(t *testing.T) {
	t.Parallel()
	assert.True(t, policy.RequestFacts{RequiredDepartmentLevel: policy.LevelApprover}.RequiresApproverGate())
	assert.False(t, policy.RequestFacts{RequiredDepartmentLevel: policy.LevelReviewer}.RequiresApproverGate())
	assert.False(t, policy.RequestFacts{}.RequiresApproverGate())
}

func TestRequestFacts_RequiresTenderACL(t *testing.T) {
	t.Parallel()
	assert.True(t, policy.RequestFacts{TenderID: "t1", TenderRestricted: true}.RequiresTenderACL())
	assert.False(t, policy.RequestFacts{TenderID: "t1", TenderRestricted: false}.RequiresTenderACL(), "unrestricted tender skips the overlay entirely")
	assert.False(t, policy.RequestFacts{TenderID: "", TenderRestricted: true}.RequiresTenderACL(), "not tender-scoped at all")
}

func TestMeetsDepartmentLevel(t *testing.T) {
	t.Parallel()
	m := domain.NewMembershipContext()
	m.Departments = []domain.Department{{DepartmentID: "eng", Level: "reviewer"}}

	assert.True(t, policy.MeetsDepartmentLevel(m, "eng", policy.LevelPreparator), "reviewer exceeds preparator")
	assert.True(t, policy.MeetsDepartmentLevel(m, "eng", policy.LevelReviewer))
	assert.False(t, policy.MeetsDepartmentLevel(m, "eng", policy.LevelApprover), "reviewer does not meet approver")
	assert.False(t, policy.MeetsDepartmentLevel(m, "sales", policy.LevelPreparator), "no membership in that department at all")
}

func TestMeetsDepartmentLevel_Delegation(t *testing.T) {
	t.Parallel()
	m := domain.NewMembershipContext()
	// No direct membership in "eng" — only a delegated approver capacity.
	m.Delegations = []domain.Delegation{{FromUserID: "boss", DepartmentID: "eng", Level: "approver"}}

	assert.True(t, policy.MeetsDepartmentLevel(m, "eng", policy.LevelApprover), "a delegation grants the delegated level")
}

func TestMeetsDepartmentLevel_BestOfMembershipAndDelegation(t *testing.T) {
	t.Parallel()
	m := domain.NewMembershipContext()
	m.Departments = []domain.Department{{DepartmentID: "eng", Level: "preparator"}}
	m.Delegations = []domain.Delegation{{FromUserID: "boss", DepartmentID: "eng", Level: "approver"}}

	assert.True(t, policy.MeetsDepartmentLevel(m, "eng", policy.LevelApprover), "the higher of direct membership and delegation applies")
}

package policy_test

import (
	"strings"
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
	cases := []struct {
		name  string
		roles []string
		want  bool
	}{
		{"tender_admin allowed", []string{"tender_admin"}, true},
		{"tenant_admin allowed (AE-50)", []string{"tenant_admin"}, true},
		{"tenant_owner allowed (AE-50)", []string{"tenant_owner"}, true},
		{"reviewer insufficient", []string{"reviewer"}, false},
		{"no roles insufficient", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			m := domain.NewMembershipContext()
			m.Roles = c.roles
			got := policy.EvaluateBase(policy.Input{
				Membership: m,
				Request:    policy.RequestFacts{Action: policy.ActionOverrideWorkflowAssignee},
			})
			assert.Equal(t, c.want, got)
		})
	}
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

// AE-52 / Billing hand-off AZ-1: only B-P14, on the token's own tenant, is
// exempt from the read-only gate; every near miss fails closed.
func TestReadOnlyExempt(t *testing.T) {
	t.Parallel()
	const tenant = "11111111-1111-1111-1111-111111111111"
	const other = "22222222-2222-2222-2222-222222222222"
	reactivate := "/api/v1/tenants/" + tenant + "/subscription/reactivate"
	cases := []struct {
		name, method, path, tenant string
		want                       bool
	}{
		{"B-P14 on own tenant", "POST", reactivate, tenant, true},
		{"query string ignored", "POST", reactivate + "?x=1", tenant, true},
		{"another tenant's path", "POST", "/api/v1/tenants/" + other + "/subscription/reactivate", tenant, false},
		{"PUT not exempt", "PUT", reactivate, tenant, false},
		{"DELETE not exempt", "DELETE", reactivate, tenant, false},
		{"trailing slash", "POST", reactivate + "/", tenant, false},
		{"deeper path", "POST", reactivate + "/extra", tenant, false},
		{"upper-case tenant", "POST", "/api/v1/tenants/" + strings.ToUpper("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa") + "/subscription/reactivate", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", false},
		{"other subscription route", "POST", "/api/v1/tenants/" + tenant + "/subscription", tenant, false},
		{"billing-contact not exempt (HLD owner decides)", "PUT", "/api/v1/tenants/" + tenant + "/billing-contact", tenant, false},
		{"empty tenant", "POST", "/api/v1/tenants//subscription/reactivate", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, policy.ReadOnlyExempt(tc.method, tc.path, tc.tenant))
		})
	}
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

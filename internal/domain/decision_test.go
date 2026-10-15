package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

func TestDenyReason_HTTPStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		reason domain.DenyReason
		status int
	}{
		{domain.DenyUnresolvableSubject, 403},
		{domain.DenyTenantReadOnly, 403},
		{domain.DenyMFAStale, 403},
		{domain.DenyTenderACLInsufficient, 403},
		{domain.DenyRoleInsufficient, 403},
		{domain.DenyServiceUnavailable, 503},
		{domain.DenyMalformedIdentity, 401},
	}
	for _, c := range cases {
		assert.Equal(t, c.status, c.reason.HTTPStatus(), "reason %s", c.reason)
	}
}

func TestTenderACL_Satisfies(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		acl      domain.TenderACL
		required string
		want     bool
	}{
		{"no access never satisfies", domain.TenderACL{HasAccess: false, AccessLevel: strPtr(domain.AccessLevelApprove)}, domain.AccessLevelView, false},
		{"view satisfies view", domain.TenderACL{HasAccess: true, AccessLevel: strPtr(domain.AccessLevelView)}, domain.AccessLevelView, true},
		{"view does not satisfy edit", domain.TenderACL{HasAccess: true, AccessLevel: strPtr(domain.AccessLevelView)}, domain.AccessLevelEdit, false},
		{"approve satisfies view", domain.TenderACL{HasAccess: true, AccessLevel: strPtr(domain.AccessLevelApprove)}, domain.AccessLevelView, true},
		{"approve satisfies edit", domain.TenderACL{HasAccess: true, AccessLevel: strPtr(domain.AccessLevelApprove)}, domain.AccessLevelEdit, true},
		{"unrecognized granted level never satisfies", domain.TenderACL{HasAccess: true, AccessLevel: strPtr("bogus")}, domain.AccessLevelView, false},
		{"unrecognized required level never satisfies", domain.TenderACL{HasAccess: true, AccessLevel: strPtr(domain.AccessLevelApprove)}, "bogus", false},
		{"nil access level never satisfies (absent on wire — TAC-GAP-001)", domain.TenderACL{HasAccess: true, AccessLevel: nil}, domain.AccessLevelView, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, c.want, c.acl.Satisfies(c.required))
		})
	}
}

func strPtr(s string) *string { return &s }

func TestTenderACL_UnmarshalJSON_InvalidJSON_ReturnsError(t *testing.T) {
	t.Parallel()
	var acl domain.TenderACL
	err := acl.UnmarshalJSON([]byte("not-json"))
	assert.Error(t, err, "completely invalid JSON must propagate a parse error")
}

func TestTenderACL_UnmarshalJSON_InvalidExpiresAt_ReturnsError(t *testing.T) {
	t.Parallel()
	var acl domain.TenderACL
	err := acl.UnmarshalJSON([]byte(`{"has_access":true,"expires_at":"not-a-timestamp"}`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expires_at")
}

func TestDenyReason_HTTPStatus_UnknownReasonDefaultsTo403(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 403, domain.DenyReason("bogus").HTTPStatus())
}

func TestAllowed_BuildsAllowDecisionWithHeaders(t *testing.T) {
	t.Parallel()
	headers := map[string]string{domain.HeaderTenantID: "t1"}
	d := domain.Allowed(headers)
	assert.True(t, d.Allow)
	assert.Equal(t, headers, d.Headers)
	assert.Empty(t, d.Reason)
}

func TestDenied_BuildsDenyDecisionWithReason(t *testing.T) {
	t.Parallel()
	d := domain.Denied(domain.DenyRoleInsufficient)
	assert.False(t, d.Allow)
	assert.Equal(t, domain.DenyRoleInsufficient, d.Reason)
	assert.Empty(t, d.Headers)
}

func TestNewMembershipContext_EmptyListsNeverNil(t *testing.T) {
	t.Parallel()
	m := domain.NewMembershipContext()
	assert.NotNil(t, m.Roles)
	assert.NotNil(t, m.Departments)
	assert.Empty(t, m.Roles)
	assert.Empty(t, m.Departments)
}

func TestNewTenantContext_EmptyListsNeverNil(t *testing.T) {
	t.Parallel()
	tc := domain.NewTenantContext()
	assert.NotNil(t, tc.FeatureFlags)
	assert.Empty(t, tc.FeatureFlags)
}

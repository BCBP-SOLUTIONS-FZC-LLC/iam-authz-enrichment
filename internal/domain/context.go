package domain

import "time"

// Department is a single department membership at a specific level
// (preparator/reviewer/approver, per the parent HLD's three-level model).
type Department struct {
	DepartmentID string `json:"department_id"`
	Level        string `json:"level"`
}

// MembershipContext holds the per-user membership facts cached under
// ae:ctx:{tenant}:{user} (LLD §4.1) — everything except mfa_freshness_seconds,
// which is never cached here (§4.4).
//
// List fields are never nil — always an explicit empty slice on zero results.
// This is a contract-test requirement (§12): callers must be able to range
// over these without a nil check, and "empty" must be distinguishable on the
// wire from "field omitted".
type MembershipContext struct {
	Roles       []string     `json:"roles"`
	Departments []Department `json:"departments"`
}

// TenantContext holds the tenant-scoped facts cached under ae:tenant:{tenant}
// (LLD §4.1) — split from MembershipContext by construction so a single
// tenant-wide event (plan change, cancellation) is always a single-key
// eviction, never a SCAN across every user in the tenant.
type TenantContext struct {
	Plan               string   `json:"plan"`
	FeatureFlags       []string `json:"feature_flags"`
	SubscriptionStatus string   `json:"subscription_status"`
	ReadOnly           bool     `json:"read_only"`
}

// NewMembershipContext returns a MembershipContext with all list fields
// initialized to empty (never nil) slices.
func NewMembershipContext() MembershipContext {
	return MembershipContext{
		Roles:       []string{},
		Departments: []Department{},
	}
}

// NewTenantContext returns a TenantContext with FeatureFlags initialized to
// an empty (never nil) slice.
func NewTenantContext() TenantContext {
	return TenantContext{FeatureFlags: []string{}}
}

// TenderACL is the result of the tender-ACL overlay check (I-12). Cacheable
// under the normal 15s TTL — unlike the membership rebuild, this endpoint
// never returns 404; absence of a grant is HasAccess: false.
type TenderACL struct {
	HasAccess   bool      `json:"has_access"`
	AccessLevel string    `json:"access_level"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// AccessLevel constants for TenderACL.AccessLevel, ordered weakest to
// strongest (§3.1 step 4: "view"/"edit"/"approve").
const (
	AccessLevelView    = "view"
	AccessLevelEdit    = "edit"
	AccessLevelApprove = "approve"
)

// accessLevelRank orders levels so a granted level can be checked against a
// required level (e.g. "approve" grant satisfies a "view" requirement).
var accessLevelRank = map[string]int{
	AccessLevelView:    1,
	AccessLevelEdit:    2,
	AccessLevelApprove: 3,
}

// Satisfies reports whether this ACL's granted level meets or exceeds the
// required level. An unrecognized level never satisfies anything.
func (a TenderACL) Satisfies(required string) bool {
	if !a.HasAccess {
		return false
	}
	granted, ok := accessLevelRank[a.AccessLevel]
	if !ok {
		return false
	}
	need, ok := accessLevelRank[required]
	if !ok {
		return false
	}
	return granted >= need
}

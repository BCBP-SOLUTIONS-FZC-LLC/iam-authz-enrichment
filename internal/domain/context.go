package domain

import (
	"encoding/json"
	"fmt"
	"time"
)

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

// TenderACL is the result of the tender-ACL overlay check (TAC-4). Cacheable
// under the normal 15s TTL — unlike the membership rebuild, this endpoint
// never returns 404; absence of a grant is HasAccess: false.
//
// AccessLevel is a pointer so that an absent field on the wire (which
// iam-tender-acl omits via omitempty when HasAccess is false) is represented
// as nil rather than an empty string — making the "no level granted" case
// unambiguous and distinguishable from an explicit empty-string value.
// Callers must use Satisfies() rather than inspecting AccessLevel directly.
type TenderACL struct {
	HasAccess   bool      `json:"has_access"`
	AccessLevel *string   `json:"access_level"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// UnmarshalJSON implements json.Unmarshaler. It decodes access_level as
// *string so an absent field (omitempty on the wire when HasAccess=false)
// becomes nil rather than an empty string — TAC-GAP-001. It also tolerates
// an empty-string or null expires_at (treating both as zero time) so a
// misconfigured test double or an unexpected wire edge case does not silently
// fail closed to DENY_TENDER_ACL_INSUFFICIENT on an otherwise-valid grant.
func (a *TenderACL) UnmarshalJSON(data []byte) error {
	type wire struct {
		HasAccess   bool    `json:"has_access"`
		AccessLevel *string `json:"access_level"`
		ExpiresAt   string  `json:"expires_at"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	a.HasAccess = w.HasAccess
	a.AccessLevel = w.AccessLevel
	if w.ExpiresAt != "" {
		// RFC3339Nano accepts both "2006-01-02T15:04:05Z" (no fractional
		// seconds) and "2006-01-02T15:04:05.999999999Z" — unlike RFC3339
		// which rejects any fractional-second suffix. Using RFC3339Nano here
		// ensures the Valkey round-trip is safe even if ExpiresAt is ever
		// constructed with non-zero nanoseconds (e.g. in tests via time.Now()).
		t, err := time.Parse(time.RFC3339Nano, w.ExpiresAt)
		if err != nil {
			return fmt.Errorf("expires_at: %w", err)
		}
		a.ExpiresAt = t
	}
	return nil
}

// BatchTenderACLItem is one entry in a TAC-5 batch authorization check
// request (iam-tender-acl POST /internal/tenants/:id/acl/batch-check).
type BatchTenderACLItem struct {
	TenderID string `json:"tender_id"`
	UserID   string `json:"user_id"`
}

// BatchTenderACLResult is one entry in a TAC-5 batch authorization check
// response. Same never-404 posture as TAC-4 — a missing grant appears as
// HasAccess:false. ExpiresAt zero means the grant has no expiry set.
type BatchTenderACLResult struct {
	TenderID    string    `json:"tender_id"`
	UserID      string    `json:"user_id"`
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
// required level. A nil AccessLevel (absent on the wire) or an unrecognized
// level never satisfies anything — both fail closed.
func (a TenderACL) Satisfies(required string) bool {
	if !a.HasAccess {
		return false
	}
	if a.AccessLevel == nil {
		return false
	}
	granted, ok := accessLevelRank[*a.AccessLevel]
	if !ok {
		return false
	}
	need, ok := accessLevelRank[required]
	if !ok {
		return false
	}
	return granted >= need
}

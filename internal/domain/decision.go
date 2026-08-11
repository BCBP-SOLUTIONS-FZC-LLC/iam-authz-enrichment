// Package domain holds pure value types and the decision/deny-reason model.
// Nothing here imports any other internal package (§1 Clean Architecture: domain is importless).
package domain

// DenyReason is the typed enum from LLD §9. Every Deny carries exactly one of
// these, chosen by the §3.1 precedence order — never by whichever check a
// given code path happens to run first.
type DenyReason string

const (
	DenyUnresolvableSubject   DenyReason = "DENY_UNRESOLVABLE_SUBJECT"
	DenyTenantReadOnly        DenyReason = "DENY_TENANT_READ_ONLY"
	DenyMFAStale              DenyReason = "DENY_MFA_STALE"
	DenyTenderACLInsufficient DenyReason = "DENY_TENDER_ACL_INSUFFICIENT"
	DenyRoleInsufficient      DenyReason = "DENY_ROLE_INSUFFICIENT"
	DenyServiceUnavailable    DenyReason = "DENY_SERVICE_UNAVAILABLE"
	DenyMalformedIdentity     DenyReason = "DENY_MALFORMED_IDENTITY"
)

// HTTPStatus maps a DenyReason to the status Envoy should surface to the
// caller (§9 table). DENY_SERVICE_UNAVAILABLE is the one 5xx-class reason —
// callers/operators must be able to distinguish "not authorized" from "the
// authz system itself is degraded".
func (r DenyReason) HTTPStatus() int {
	switch r {
	case DenyMalformedIdentity:
		return 401
	case DenyServiceUnavailable:
		return 503
	case DenyUnresolvableSubject, DenyTenantReadOnly, DenyMFAStale, DenyTenderACLInsufficient, DenyRoleInsufficient:
		return 403
	default:
		return 403
	}
}

// InjectedHeaders are the six trust-boundary headers this service injects on
// Allow. Every downstream service trusts these implicitly (mTLS-enforced
// mesh) — no other header on the inbound CheckRequest may influence them.
const (
	HeaderTenantID     = "x-tenant-id"
	HeaderUserID       = "x-user-id"
	HeaderDepartments  = "x-departments"
	HeaderTenantRoles  = "x-tenant-roles"
	HeaderPlan         = "x-plan"
	HeaderFeatureFlags = "x-feature-flags"
)

// CacheResult reports what state a jittered-TTL cache lookup found. It lives
// in domain (not the valkey adapter) so both the outbound adapter that
// produces it and the usecase layer that consumes it can depend on it
// without the usecase layer importing an adapter package.
type CacheResult int

const (
	// CacheMiss: no key present at all (past its physical TTL, or never set).
	CacheMiss CacheResult = iota
	// CacheFresh: present and within its normal (soft) TTL window.
	CacheFresh
	// CacheStale: present but past its soft TTL — only usable under §7's
	// stale-if-error rule when the sibling service is unreachable.
	CacheStale
)

// Decision is the outcome of policy evaluation. On Allow, Headers holds
// exactly the six InjectedHeaders values. On Deny, Reason is set and Headers
// is empty.
type Decision struct {
	Allow   bool
	Reason  DenyReason
	Headers map[string]string
}

// Allowed builds an Allow decision with the six trust-boundary headers.
func Allowed(headers map[string]string) Decision {
	return Decision{Allow: true, Headers: headers}
}

// Denied builds a Deny decision for the given reason.
func Denied(reason DenyReason) Decision {
	return Decision{Allow: false, Reason: reason}
}

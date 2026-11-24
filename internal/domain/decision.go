// Package domain holds pure value types and the decision/deny-reason model.
// Nothing here imports any other internal package (§1 Clean Architecture: domain is importless).
package domain

// DenyReason is the typed enum from LLD §9. Every Deny carries exactly one of
// these, chosen by the §3.1 precedence order — never by whichever check a
// given code path happens to run first.
type DenyReason string

const (
	DenyUnresolvableSubject DenyReason = "DENY_UNRESOLVABLE_SUBJECT"
	// DenyMemberSuspended is step 1's deny for a caller whose membership row
	// exists but is suspended (I-8 200, status "suspended"; LLD §8.2.1,
	// §16 AE-51). Distinct from DenyUnresolvableSubject so the frontend can
	// tell "access paused" from "not a member" (web-shell AZ-2).
	DenyMemberSuspended       DenyReason = "DENY_MEMBER_SUSPENDED"
	DenyTenantReadOnly        DenyReason = "DENY_TENANT_READ_ONLY"
	DenyMFAStale              DenyReason = "DENY_MFA_STALE"
	DenyTenderACLInsufficient DenyReason = "DENY_TENDER_ACL_INSUFFICIENT"
	DenyRoleInsufficient      DenyReason = "DENY_ROLE_INSUFFICIENT"
	DenyServiceUnavailable    DenyReason = "DENY_SERVICE_UNAVAILABLE"
	DenyMalformedIdentity     DenyReason = "DENY_MALFORMED_IDENTITY"
)

// DenyReasons returns every DenyReason, in §3.1 precedence order (identity,
// subject resolution, read-only, role, tender ACL, MFA, then the 503 that can
// short-circuit anywhere). A new reason must be added here and to
// api/deny-codes.json in the same position: TestDenyCodesJSON_MatchesDenyReasons
// compares the two by position, and TestDenyReasons_CoversEveryConst fails
// if a DenyReason const is missing here.
func DenyReasons() []DenyReason {
	return []DenyReason{
		DenyMalformedIdentity,
		DenyUnresolvableSubject,
		DenyMemberSuspended,
		DenyTenantReadOnly,
		DenyRoleInsufficient,
		DenyTenderACLInsufficient,
		DenyMFAStale,
		DenyServiceUnavailable,
	}
}

// NegativeCacheReason turns a stored ae:neg value back into its deny reason.
// Only the two subject-resolution reasons can be negative-cached (§4.3,
// §16 AE-51): DENY_MEMBER_SUSPENDED is kept, and anything else — the "1"
// written before AE-51, an empty value, or any other DenyReason — reads as
// DENY_UNRESOLVABLE_SUBJECT, so a bad entry can never turn into a 401 or 503.
func NegativeCacheReason(v string) DenyReason {
	if DenyReason(v) == DenyMemberSuspended {
		return DenyMemberSuspended
	}
	return DenyUnresolvableSubject
}

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
	case DenyUnresolvableSubject, DenyMemberSuspended, DenyTenantReadOnly, DenyMFAStale, DenyTenderACLInsufficient, DenyRoleInsufficient:
		return 403
	default:
		return 403
	}
}

// InjectedHeaders are the trust-boundary headers this service injects on Allow.
// The seven permanent headers are always present. HeaderAuthTime is additionally
// injected when the JWT includes a non-zero auth_time claim (LLD §16 AE-49).
// Every downstream service trusts these implicitly (mTLS-enforced mesh) — no
// other header on the inbound CheckRequest may influence them.
const (
	HeaderTenantID     = "x-tenant-id"
	HeaderUserID       = "x-user-id"
	HeaderDepartments  = "x-departments"
	HeaderTenantRoles  = "x-tenant-roles"
	HeaderPlan         = "x-plan"
	HeaderFeatureFlags = "x-feature-flags"
	// HeaderResidencyMode is the tenant's data-residency mode (LLD §5.3, §16 AE-40,
	// CD-37). Values: "standard" | "strict". Always server-computed — never
	// read from the inbound request (ingress strips it; AuthZ overwrites). Consumed
	// by LLM services and forwarded to the Model Gateway. On Allow path only.
	HeaderResidencyMode = "x-residency-mode"
	// HeaderAuthTime carries the JWT auth_time claim as an RFC 3339 UTC string
	// (e.g. "2026-10-29T14:32:00Z"). Injected only when auth_time is non-zero;
	// omitted entirely when the claim is absent or zero. Used by Tender Service
	// to populate mfa_verified_at in approval evidence (LLD §16 AE-49, AE-TND-F1).
	HeaderAuthTime = "x-auth-time"
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

// Decision is the outcome of policy evaluation. On Allow, Headers holds the
// seven permanent injected headers plus x-auth-time when the JWT auth_time
// claim is non-zero. On Deny, Reason is set and Headers is empty.
type Decision struct {
	Allow   bool
	Reason  DenyReason
	Headers map[string]string
}

// Allowed builds an Allow decision with the injected trust-boundary headers.
func Allowed(headers map[string]string) Decision {
	return Decision{Allow: true, Headers: headers}
}

// Denied builds a Deny decision for the given reason.
func Denied(reason DenyReason) Decision {
	return Decision{Allow: false, Reason: reason}
}

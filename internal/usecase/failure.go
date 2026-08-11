package usecase

// This file is the LLD §7 failure-handling matrix as an explicit, directly
// testable decision function — not scattered `if err != nil` handling
// throughout check.go. Each row of the doc's table has a corresponding case
// below and a corresponding test in test/unit/usecase.

// DependencyOutcome is what check.go should do once it has observed the
// state of this request's two dependencies (Valkey and the Org & Membership
// sibling service) while resolving membership+tenant context.
type DependencyOutcome int

const (
	// OutcomeNormal: proceed using whatever fresh/live data was obtained.
	// Covers the healthy path AND §7 row 1 (Valkey unreachable, sibling
	// healthy — bypass the cache and call the sibling directly on every
	// request; accept degraded latency; correctness is preserved because the
	// sibling is still authoritative and reachable, so this must NOT fail
	// closed).
	OutcomeNormal DependencyOutcome = iota
	// OutcomeServeStale: §7 row 2 — the sibling is unreachable/timing out,
	// Valkey is healthy, and a stale (past its soft TTL, still within the
	// 5-minute hard-capped grace window) ae:ctx+ae:tenant pair exists to
	// serve instead.
	OutcomeServeStale
	// OutcomeFailClosed: §7 row 3 — both dependencies are unreachable, or
	// the sibling is unreachable and there is nothing stale to fall back on
	// (the degenerate case of row 2 when nothing was ever cached for this
	// subject). Maps to DENY_SERVICE_UNAVAILABLE / 503, never DENY-as-403 —
	// callers/operators must be able to tell "not authorized" apart from
	// "the authz system itself is degraded".
	OutcomeFailClosed
)

// DependencyState is the state observed while resolving a subject's
// membership+tenant context for one request.
type DependencyState struct {
	// ValkeyReachable is false only on a connection-level Valkey error —
	// never merely on a cache miss.
	ValkeyReachable bool
	// SiblingReachable is false only on a timeout/network/5xx from the
	// membership-rebuild call. A 404 is NOT unreachable — it's I-8's
	// authoritative "no active membership" answer, handled by §3.1 step 1
	// before this decision is ever consulted.
	SiblingReachable bool
	// StaleEntryAvailable: a Stale (not Fresh, not Miss) ae:ctx AND
	// ae:tenant pair both exist for this (tenant, user). Only meaningful
	// when ValkeyReachable is true.
	StaleEntryAvailable bool
}

// DecideDependencyOutcome applies the §7 matrix to the observed state.
func DecideDependencyOutcome(s DependencyState) DependencyOutcome {
	if s.SiblingReachable {
		return OutcomeNormal
	}
	if s.ValkeyReachable && s.StaleEntryAvailable {
		return OutcomeServeStale
	}
	return OutcomeFailClosed
}

// §7's fourth row — the tender-ACL check (I-12) specifically timing out or
// erroring — has no DependencyState/DecideDependencyOutcome involvement: it
// fails closed for the tender-scoped overlay ONLY (DENY_TENDER_ACL_INSUFFICIENT),
// independent of Valkey/sibling-membership availability, applied directly at
// the tender-ACL call site in check.go. It must never escalate to
// DENY_SERVICE_UNAVAILABLE or deny aspects of the request the base policy
// would otherwise allow.

package domain

import "errors"

// Sentinel errors shared between outbound adapters and the usecase layer
// that consumes them. Living here (not in an adapter package) keeps the
// usecase layer from ever importing an adapter package just to classify an
// error — Clean Architecture (§1): adapters depend on domain, not the other
// way around.
var (
	// ErrNotFound is I-8's 404 — no active membership. An authoritative
	// answer from a reachable sibling, not an availability failure.
	ErrNotFound = errors.New("domain: not found")
	// ErrMemberSuspended marks an I-8 answer whose membership row exists but
	// is suspended (LLD §8.2.1, §16 AE-51). Adapters return it joined with
	// ErrNotFound, so every ErrNotFound path (negative cache, ae:ctx
	// eviction) still applies; it only changes the deny reason.
	ErrMemberSuspended = errors.New("domain: member suspended")
	// ErrUnavailable wraps any network error, timeout, or unexpected
	// non-2xx/404 response from a sibling call.
	ErrUnavailable = errors.New("domain: unavailable")
)

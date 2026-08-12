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
	// ErrUnavailable wraps any network error, timeout, or unexpected
	// non-2xx/404 response from a sibling call.
	ErrUnavailable = errors.New("domain: unavailable")
)

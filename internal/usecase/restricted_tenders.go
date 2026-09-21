package usecase

import (
	"context"
	"sync"
	"time"
)

// restrictedEntry is an L1 cache line: whether (tenant, tender) is
// restricted, as of at. A positive entry is valid forever — restriction
// only ever flips false→true, never back. A negative entry is only valid
// for negTTL, since some other replica may flip it true in the store at
// any time and this replica must eventually notice.
type restrictedEntry struct {
	restricted bool
	at         time.Time
}

// RestrictedTenderSet is the "is this tender restricted" fact flipped by
// TenderRestricted (§5). L1 is in-process; L2 is Valkey
// ae:restricted:{tenant}:{tender}. Competing SQS consumers deliver each
// event to one replica — L2 is how every other replica applies the
// tender-ACL overlay.
type RestrictedTenderSet struct {
	mu     sync.RWMutex
	m      map[string]restrictedEntry // "tenant:tender" -> entry
	store  Cache                      // optional; nil in L1-only unit tests
	negTTL time.Duration              // how long a "not restricted" L1 entry is trusted before re-checking the store
}

// NewRestrictedTenderSet builds an empty set. negTTL bounds how long a
// "not restricted" result is served from L1 before IsRestricted re-checks
// the store — without it, the overwhelming majority-case (a tender that
// has never been restricted) would either never cache locally (a Valkey
// round-trip on every Check) or cache "not restricted" forever and never
// observe another replica's MarkRestricted.
func NewRestrictedTenderSet(negTTL time.Duration) *RestrictedTenderSet {
	return &RestrictedTenderSet{m: make(map[string]restrictedEntry), negTTL: negTTL}
}

// BindStore attaches the shared Valkey-backed fact store. Call once at
// wiring, before serving Check or starting consumers.
func (s *RestrictedTenderSet) BindStore(store Cache) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = store
}

func restrictedKey(tenant, tender string) string {
	return tenant + ":" + tender
}

// MarkRestricted flags (tenant, tender) as restricted. Writes the store
// first so other replicas observe it, then L1. A store error is returned
// so SQS retries the event.
func (s *RestrictedTenderSet) MarkRestricted(ctx context.Context, tenant, tender string) error {
	s.mu.RLock()
	store := s.store
	s.mu.RUnlock()
	if store != nil {
		if err := store.SetRestricted(ctx, tenant, tender); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[restrictedKey(tenant, tender)] = restrictedEntry{restricted: true}
	return nil
}

// IsRestricted reports whether (tenant, tender) is flagged restricted.
// L1 first; on a miss or a stale negative, L2. A store error is treated
// as "not restricted" so a Valkey outage degrades to the same posture as
// a replica that has not yet seen the event — membership §7 still owns
// fail-open, not this fact.
func (s *RestrictedTenderSet) IsRestricted(ctx context.Context, tenant, tender string) bool {
	key := restrictedKey(tenant, tender)
	s.mu.RLock()
	if e, ok := s.m[key]; ok && (e.restricted || time.Since(e.at) <= s.negTTL) {
		s.mu.RUnlock()
		return e.restricted
	}
	store := s.store
	s.mu.RUnlock()
	if store == nil {
		return false
	}
	ok, err := store.GetRestricted(ctx, tenant, tender)
	s.mu.Lock()
	// A concurrent MarkRestricted may have landed a positive entry while
	// this GetRestricted was in flight (it started from a stale/expired
	// negative). Never let a negative result clobber that — restriction
	// only ever flips false→true, never back.
	if cur, exists := s.m[key]; exists && cur.restricted {
		s.mu.Unlock()
		return true
	}
	if err != nil {
		// Transient store failure: fail open for this call only (matching
		// the doc comment above), but do NOT cache it — caching it would
		// extend a single blip into a full negTTL window of "not
		// restricted", silently bypassing the tender-ACL overlay for that
		// whole window instead of just this one request.
		s.mu.Unlock()
		return false
	}
	s.m[key] = restrictedEntry{restricted: ok, at: time.Now()}
	s.mu.Unlock()
	return ok
}

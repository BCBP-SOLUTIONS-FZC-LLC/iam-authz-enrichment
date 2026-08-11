package usecase

import "sync"

// RestrictedTenderSet is the in-memory "is this tender restricted" fact
// flipped by the tender-authz-q consumer's TenderRestricted event (§5). Not
// a cache eviction — this is standalone in-process state consulted by the
// tender-ACL overlay policy (§3.1 step 4) to decide whether that overlay
// applies at all.
type RestrictedTenderSet struct {
	mu sync.RWMutex
	m  map[string]struct{} // "tenant:tender" -> present
}

// NewRestrictedTenderSet builds an empty set.
func NewRestrictedTenderSet() *RestrictedTenderSet {
	return &RestrictedTenderSet{m: make(map[string]struct{})}
}

func restrictedKey(tenant, tender string) string {
	return tenant + ":" + tender
}

// MarkRestricted flags (tenant, tender) as restricted.
func (s *RestrictedTenderSet) MarkRestricted(tenant, tender string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[restrictedKey(tenant, tender)] = struct{}{}
}

// IsRestricted reports whether (tenant, tender) is flagged restricted.
func (s *RestrictedTenderSet) IsRestricted(tenant, tender string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.m[restrictedKey(tenant, tender)]
	return ok
}

package usecase

import "sync"

// RealmMap is the in-process realm→tenant map for dedicated-realm tenants
// (§2 point 3). It is seeded at startup (there is no database to rebuild it
// from) and kept fresh at runtime by the tenant-authz-q consumer, which
// updates it directly from TenantConverted/TenantRealmReady event payloads —
// both events must update it (§5's explicit warning: a newly-dedicated realm
// created via direct-paid signup fires only TenantRealmReady, not
// TenantConverted, so wiring only one leaves a real gap).
type RealmMap struct {
	mu sync.RWMutex
	m  map[string]string // realm issuer -> tenant_id
}

// NewRealmMap builds a RealmMap from a startup seed (may be empty/nil).
func NewRealmMap(seed map[string]string) *RealmMap {
	m := make(map[string]string, len(seed))
	for k, v := range seed {
		m[k] = v
	}
	return &RealmMap{m: m}
}

// Lookup returns the tenant mapped to realm, if any.
func (r *RealmMap) Lookup(realm string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenant, ok := r.m[realm]
	return tenant, ok
}

// Set inserts or updates the realm -> tenant mapping. Called by the
// tenant-authz-q consumer on both TenantConverted and TenantRealmReady.
func (r *RealmMap) Set(realm, tenant string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[realm] = tenant
}

// Claims is the subset of Envoy-jwt_authn-validated JWT claims this service
// trusts (§8.1 invariant AE-SEC-1 — no other claim or header is a valid
// identity/authz input). Decoded, never independently validated: signature/
// iss/aud/exp checking is exclusively jwt_authn's job, already done before
// this service is ever called.
type Claims struct {
	Subject  string // "sub"
	Issuer   string // "iss"
	TenantID string // "tenant_id" — shared trial-realm tenants only
	AuthTime int64  // "auth_time", unix seconds
}

// ResolveTenant implements §2 point 3: resolve tenant_id from the JWT iss
// claim for dedicated-realm tenants (via realmMap), or from the
// Keycloak-populated tenant_id claim for shared trial-realm tenants.
// Returns ok=false (→ DENY_MALFORMED_IDENTITY, §3.1/§9) when iss matches
// neither a known dedicated realm nor the configured shared realm.
func ResolveTenant(claims Claims, realmMap *RealmMap, sharedRealmIssuer string) (string, bool) {
	if claims.Issuer == "" {
		return "", false
	}
	if tenant, ok := realmMap.Lookup(claims.Issuer); ok {
		return tenant, true
	}
	if sharedRealmIssuer != "" && claims.Issuer == sharedRealmIssuer && claims.TenantID != "" {
		return claims.TenantID, true
	}
	return "", false
}

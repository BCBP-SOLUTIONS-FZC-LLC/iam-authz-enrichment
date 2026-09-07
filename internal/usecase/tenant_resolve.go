package usecase

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// realmEntry is an L1 cache line for one issuer: the tenant it resolves to,
// if any, as of at. A positive entry (found=true) is valid forever — once
// an issuer maps to a tenant it is never unmapped. A negative entry is
// only valid for negTTL, since another replica may Set() it at any time
// and this replica must eventually notice.
type realmEntry struct {
	tenant string
	found  bool
	at     time.Time
}

// RealmMap is the realm→tenant map for dedicated-realm tenants (§2 point 3).
// L1 is in-process (seed + events this pod consumed). L2 is Valkey
// ae:realm:{issuer}, written on Set so competing-consumer replicas that
// never saw the SQS message still resolve the dedicated issuer.
type RealmMap struct {
	mu     sync.RWMutex
	m      map[string]realmEntry // realm issuer -> entry
	store  Cache                 // optional; nil in unit tests that only exercise L1
	negTTL time.Duration         // how long a "no such realm" L1 entry is trusted before re-checking the store
}

// NewRealmMap builds a RealmMap from a startup seed (may be empty/nil).
// negTTL bounds how long a "not found" result is served from L1 before
// re-checking the store — without it, every request whose issuer never
// resolves (a malformed/unknown issuer, or an attacker probe) would either
// never cache locally (a Valkey round-trip on every such Check, forever)
// or cache "not found" forever and never observe another replica's Set.
func NewRealmMap(seed map[string]string, negTTL time.Duration) *RealmMap {
	m := make(map[string]realmEntry, len(seed))
	for k, v := range seed {
		m[k] = realmEntry{tenant: v, found: true}
	}
	return &RealmMap{m: m, negTTL: negTTL}
}

// BindStore attaches the shared Valkey-backed fact store. Call once at
// wiring, before serving Check or starting consumers.
func (r *RealmMap) BindStore(store Cache) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.store = store
}

// PersistSeed writes the startup seed into the store so a replica that
// starts after another pod already received TenantConverted still has
// those mappings if they were also in the seed — and so event-written
// keys have a consistent namespace from process start. Best-effort:
// L1 is unchanged regardless of outcome. Every entry is attempted even if
// one fails — map iteration order is randomized, so returning on the
// first error would leave a non-deterministic, arbitrary subset of the
// seed persisted across restarts. Any failures are joined into one error.
func (r *RealmMap) PersistSeed(ctx context.Context) error {
	r.mu.RLock()
	store := r.store
	snapshot := make(map[string]string, len(r.m))
	for k, v := range r.m {
		if v.found {
			snapshot[k] = v.tenant
		}
	}
	r.mu.RUnlock()
	if store == nil {
		return nil
	}
	var errs []error
	for realm, tenant := range snapshot {
		if err := store.SetRealm(ctx, realm, tenant); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", realm, err))
		}
	}
	return errors.Join(errs...)
}

// Lookup returns the tenant mapped to realm, if any. L1 first (including a
// still-fresh negative result); on a miss or an expired negative, L2
// (store). A store error is treated as a miss so Check can still resolve
// from seed / shared-realm without failing closed on Valkey-down.
func (r *RealmMap) Lookup(ctx context.Context, realm string) (string, bool) {
	tenant, found, freshNegative := r.lookupLocal(realm)
	if found || freshNegative {
		return tenant, found
	}
	return r.lookupStore(ctx, realm)
}

// Set inserts or updates the realm → tenant mapping. Writes the store
// first so other replicas can observe it, then L1. A store error is
// returned so SQS retries the event.
func (r *RealmMap) Set(ctx context.Context, realm, tenant string) error {
	r.mu.RLock()
	store := r.store
	r.mu.RUnlock()
	if store != nil {
		if err := store.SetRealm(ctx, realm, tenant); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[realm] = realmEntry{tenant: tenant, found: true}
	return nil
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
//
// Shared-realm matching runs before the store lookup so every shared-trial
// Check does not pay a Valkey GET for an issuer that will never be in
// ae:realm. A still-fresh negative L1 result short-circuits the same way,
// so an issuer that resolves to nothing does not pay a Valkey GET on every
// single Check either — only once per negTTL window.
func ResolveTenant(ctx context.Context, claims Claims, realmMap *RealmMap, sharedRealmIssuer string) (string, bool) {
	if claims.Issuer == "" {
		return "", false
	}
	tenant, found, freshNegative := realmMap.lookupLocal(claims.Issuer)
	if found {
		return tenant, true
	}
	if sharedRealmIssuer != "" && claims.Issuer == sharedRealmIssuer && claims.TenantID != "" {
		return claims.TenantID, true
	}
	if freshNegative {
		return "", false
	}
	if tenant, ok := realmMap.lookupStore(ctx, claims.Issuer); ok {
		return tenant, true
	}
	return "", false
}

// lookupLocal checks only L1. found is true only for a positive entry.
// freshNegative is true when L1 holds a negative entry still inside
// negTTL — the caller should trust it (a miss) without going to the store.
// Both false means "unknown or expired" — the caller must check the store.
func (r *RealmMap) lookupLocal(realm string) (tenant string, found bool, freshNegative bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, exists := r.m[realm]
	if !exists {
		return "", false, false
	}
	if e.found {
		return e.tenant, true, false
	}
	if time.Since(e.at) <= r.negTTL {
		return "", false, true
	}
	return "", false, false
}

// lookupStore checks the store (L2) and updates L1 with the result.
func (r *RealmMap) lookupStore(ctx context.Context, realm string) (string, bool) {
	r.mu.RLock()
	store := r.store
	r.mu.RUnlock()
	if store == nil {
		return "", false
	}
	tenant, ok, err := store.GetRealm(ctx, realm)
	r.mu.Lock()
	// A concurrent Set may have landed a positive entry while this
	// GetRealm was in flight (it started from a stale/expired negative
	// or from no entry at all). Never let a negative result clobber
	// that — once mapped, an issuer is never unmapped.
	if cur, exists := r.m[realm]; exists && cur.found {
		r.mu.Unlock()
		return cur.tenant, true
	}
	if err != nil {
		// Transient store failure: treat as a miss for this call only
		// (Check can still resolve from seed/shared-realm without failing
		// closed on Valkey-down), but do NOT cache it — caching it would
		// extend a single blip into a full negTTL window of denials for a
		// real dedicated-realm issuer instead of just this one request.
		r.mu.Unlock()
		return "", false
	}
	if ok {
		r.m[realm] = realmEntry{tenant: tenant, found: true}
	} else {
		r.m[realm] = realmEntry{found: false, at: time.Now()}
	}
	r.mu.Unlock()
	return tenant, ok
}

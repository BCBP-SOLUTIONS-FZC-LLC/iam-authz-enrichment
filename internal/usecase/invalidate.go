package usecase

import (
	"context"
	"fmt"
)

// Invalidator implements the event-driven cache eviction from LLD §5. Each
// Handle* method corresponds to one row of that section's table — the
// consumer adapter (internal/adapter/inbound/consumer) decodes an
// Envelope[json.RawMessage] payload into the matching *EventPayload type
// below and calls the matching method, after the consumer adapter's
// platform-events processed_events check (IdempotencyStore / Envelope.ID)
// has confirmed this event hasn't already been applied.
type Invalidator struct {
	cache      Cache
	realmMap   *RealmMap
	restricted *RestrictedTenderSet
	log        Logger
}

// NewInvalidator builds an Invalidator.
func NewInvalidator(cache Cache, realmMap *RealmMap, restricted *RestrictedTenderSet, log Logger) *Invalidator {
	return &Invalidator{cache: cache, realmMap: realmMap, restricted: restricted, log: log}
}

// MembershipEventPayload is membership-authz-q's decoded payload —
// DepartmentMembershipGranted/Revoked/LevelChanged, TenantRoleGranted/
// Revoked, and MembershipRevoked all carry the same {user_id, ...} shape;
// this service evicts rather than patches, so it doesn't need to know which
// specific fact changed. MembershipRevoked additionally carries an
// optional actor_id (LLD §16 AE-20), ignored here like every other unused
// wire field.
type MembershipEventPayload struct {
	UserID string `json:"user_id"`
}

// HandleMembershipEvent evicts ae:ctx:{tenant}:{user} for any
// membership-authz-q event type.
func (inv *Invalidator) HandleMembershipEvent(ctx context.Context, tenant string, p MembershipEventPayload) error {
	if err := inv.cache.EvictMembershipContext(ctx, tenant, p.UserID); err != nil {
		return fmt.Errorf("evict ae:ctx: %w", err)
	}
	// §4.3: the same grant events that would populate a positive ae:ctx
	// entry must also evict ae:neg early. Doing this unconditionally for
	// every membership event (grant, revoke, or level change) is a safe
	// superset — a revoke/level-change simply costs one extra rebuild call
	// on the next lookup instead of a negative-cache hit, never a
	// correctness problem.
	if err := inv.cache.EvictNegative(ctx, tenant, p.UserID); err != nil {
		return fmt.Errorf("evict ae:neg: %w", err)
	}
	return nil
}

// HandleMembershipRevoked evicts ae:ctx/ae:neg plus every ae:tender_acl
// entry for the user, best-effort (LLD §16 AE-20). MembershipRevoked is Org
// & Membership's per-user removal cascade signal: a full member removal
// soft-deletes the tenant_memberships row and leaves the user's role/dept
// grants inert rather than firing per-grant *Revoked events, so this is the
// only membership-authz-q event that fires on a whole-membership removal —
// without it, ae:ctx would serve a stale Allow until its 60s TTL. Same
// best-effort tender-ACL semantics as HandleUserDeleted: a partial scan
// failure degrades to "stale until its 15s TTL expires", not a correctness
// failure requiring retry.
func (inv *Invalidator) HandleMembershipRevoked(ctx context.Context, tenant string, p MembershipEventPayload) error {
	if err := inv.cache.EvictMembershipContext(ctx, tenant, p.UserID); err != nil {
		return fmt.Errorf("evict ae:ctx: %w", err)
	}
	if err := inv.cache.EvictNegative(ctx, tenant, p.UserID); err != nil {
		return fmt.Errorf("evict ae:neg: %w", err)
	}
	if err := inv.cache.EvictTenderACLForUser(ctx, tenant, p.UserID); err != nil {
		inv.log.Warn("best-effort tender-acl eviction failed on MembershipRevoked", map[string]interface{}{"error": err.Error()})
	}
	return nil
}

// UserEventPayload is user-authz-q's decoded payload.
type UserEventPayload struct {
	UserID        string   `json:"user_id"`
	ChangedFields []string `json:"changed_fields,omitempty"`
}

// IsEmailChange reports whether a UserUpdated event's changed_fields
// includes "email" — the §5-mandated consumer-side filter (deliberately not
// an SNS attribute filter).
func (p UserEventPayload) IsEmailChange() bool {
	for _, f := range p.ChangedFields {
		if f == "email" {
			return true
		}
	}
	return false
}

// HandleUserUpdated evicts only on an email change (§5) — any other
// changed_fields value is a no-op.
func (inv *Invalidator) HandleUserUpdated(ctx context.Context, tenant string, p UserEventPayload) error {
	if !p.IsEmailChange() {
		return nil
	}
	return inv.evictUserContext(ctx, tenant, p.UserID)
}

// HandleUserAvailabilityChanged evicts ae:ctx/ae:neg for the user.
func (inv *Invalidator) HandleUserAvailabilityChanged(ctx context.Context, tenant string, p UserEventPayload) error {
	return inv.evictUserContext(ctx, tenant, p.UserID)
}

// HandleUserDeleted evicts ae:ctx/ae:neg plus every ae:tender_acl entry for
// the user, best-effort (§5) — a partial tender-ACL scan failure degrades to
// "stale until its 15s TTL expires", not a correctness failure requiring
// retry.
func (inv *Invalidator) HandleUserDeleted(ctx context.Context, tenant string, p UserEventPayload) error {
	if err := inv.evictUserContext(ctx, tenant, p.UserID); err != nil {
		return err
	}
	if err := inv.cache.EvictTenderACLForUser(ctx, tenant, p.UserID); err != nil {
		inv.log.Warn("best-effort tender-acl eviction failed on UserDeleted", map[string]interface{}{"error": err.Error()})
	}
	return nil
}

func (inv *Invalidator) evictUserContext(ctx context.Context, tenant, user string) error {
	if err := inv.cache.EvictMembershipContext(ctx, tenant, user); err != nil {
		return fmt.Errorf("evict ae:ctx: %w", err)
	}
	if err := inv.cache.EvictNegative(ctx, tenant, user); err != nil {
		return fmt.Errorf("evict ae:neg: %w", err)
	}
	return nil
}

// HandleBillingEvent implements billing-authz-q (TenantPlanChanged,
// TenantSubscriptionCancelled, TenantReactivated): evict the tenant-scoped
// slice — one key, regardless of which of the three event types fired.
func (inv *Invalidator) HandleBillingEvent(ctx context.Context, tenant string) error {
	return inv.cache.EvictTenantContext(ctx, tenant)
}

// TenantRealmEventPayload is tenant-authz-q's decoded payload.
type TenantRealmEventPayload struct {
	Realm string `json:"realm"`
}

// HandleTenantConverted: realm strategy changed, everything's stale — evict
// the tenant-scoped slice AND refresh the realm map.
func (inv *Invalidator) HandleTenantConverted(ctx context.Context, tenant string, p TenantRealmEventPayload) error {
	if err := inv.realmMap.Set(ctx, p.Realm, tenant); err != nil {
		return fmt.Errorf("persist realm map: %w", err)
	}
	return inv.cache.EvictTenantContext(ctx, tenant)
}

// HandleTenantRealmReady: NO ae:ctx eviction — refresh the realm map only.
// Wiring this (not just TenantConverted) matters: a newly-dedicated realm
// created via direct-paid signup fires only TenantRealmReady (§5).
func (inv *Invalidator) HandleTenantRealmReady(ctx context.Context, tenant string, p TenantRealmEventPayload) error {
	if err := inv.realmMap.Set(ctx, p.Realm, tenant); err != nil {
		return fmt.Errorf("persist realm map: %w", err)
	}
	return nil
}

// TenderRestrictedPayload is tender-authz-q's decoded payload.
type TenderRestrictedPayload struct {
	TenderID string `json:"tender_id"`
}

// HandleTenderRestricted flips the restricted-tender fact (L1 + shared
// Valkey). Not a cache eviction (§5).
func (inv *Invalidator) HandleTenderRestricted(ctx context.Context, tenant string, p TenderRestrictedPayload) error {
	if err := inv.restricted.MarkRestricted(ctx, tenant, p.TenderID); err != nil {
		return fmt.Errorf("persist restricted tender: %w", err)
	}
	return nil
}

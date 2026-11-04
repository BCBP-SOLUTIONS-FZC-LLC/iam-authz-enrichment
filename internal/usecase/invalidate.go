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
	recorder   Recorder
}

// NewInvalidator builds an Invalidator. recorder is optional (variadic so all
// existing call sites compile unchanged); if omitted, a NoopRecorder is used.
// cmd/server passes the real metrics.Recorder so eviction failures are counted.
func NewInvalidator(cache Cache, realmMap *RealmMap, restricted *RestrictedTenderSet, log Logger, recorder ...Recorder) *Invalidator {
	var rec Recorder = NoopRecorder{}
	if len(recorder) > 0 && recorder[0] != nil {
		rec = recorder[0]
	}
	return &Invalidator{cache: cache, realmMap: realmMap, restricted: restricted, log: log, recorder: rec}
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
		inv.recorder.ObserveEvictionError("membership_revoked")
	}
	return nil
}

// UserEventPayload is user-authz-q's decoded payload.
type UserEventPayload struct {
	UserID        string   `json:"user_id"`
	ChangedFields []string `json:"changed_fields,omitempty"`
}

// RequiresEviction reports whether a UserUpdated event's changed_fields
// contains a value that invalidates the AE decision cache. Two values trigger
// eviction:
//
//   - "email" — the subject's identity key in Org & Membership's I-8 response
//     changes, so the cached ae:ctx entry is stale.
//   - "status" — the user has been enabled or disabled; a disabled user can no
//     longer authenticate and Org & Membership's I-8 will return 404 on the
//     next live call. Without evicting on "status", the ae:ctx entry would
//     serve stale Allow decisions for up to AE_CTX_TTL after the user is
//     disabled. UserUpdated with changed_fields=["status"] fires in the same
//     UP transaction as UserStatusChanged, but user-authz-q only subscribes to
//     UserUpdated — this consumer-side check is the only eviction path for a
//     status change (UP-AE-GAP-001).
//
// All other changed_fields values (display_name, job_title, timezone, …) are
// no-ops — they do not affect any fact the AE decision cache holds.
func (p UserEventPayload) RequiresEviction() bool {
	for _, f := range p.ChangedFields {
		if f == "email" || f == "status" {
			return true
		}
	}
	return false
}

// HandleUserUpdated evicts on an email or status change (§5); any other
// changed_fields value is a no-op.
func (inv *Invalidator) HandleUserUpdated(ctx context.Context, tenant string, p UserEventPayload) error {
	if !p.RequiresEviction() {
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
		inv.recorder.ObserveEvictionError("user_deleted")
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

// HandleTenantSettingChanged implements tenant-authz-q TenantSettingChanged
// (CD-37, LLD §16 AE-40): a tenant-owner changed a setting such as
// residency_mode, so the ae:tenant entry is stale. Evict it; the next
// request will rebuild from I-8 and pick up the new value. No payload
// decoding needed — the tenant_id on the envelope is the only fact required.
func (inv *Invalidator) HandleTenantSettingChanged(ctx context.Context, tenant string) error {
	return inv.cache.EvictTenantContext(ctx, tenant)
}

// HandleTenantLifecycleEvent evicts ae:tenant:{tenant} for Realm Provisioner
// status-change events (§5): TenantSuspended, TenantReactivated
// (operator-sourced), TrialExpired, TrialReactivated. No payload decode needed.
// TenantOffboarded is handled by HandleTenantOffboarded — it requires the
// wider cleanup of ae:realm and ae:restricted (LLD §16 AE-17).
func (inv *Invalidator) HandleTenantLifecycleEvent(ctx context.Context, tenant string) error {
	return inv.cache.EvictTenantContext(ctx, tenant)
}

// HandleTenantOffboarded handles TenantOffboarded (full realm deletion, §5).
// In addition to the ae:tenant eviction shared by all lifecycle events, it
// clears the no-TTL keys that would otherwise persist in Valkey indefinitely
// and cause stale resolution on a reused realm issuer (LLD §16 AE-17):
//
//   - ae:restricted:{tenant}:* (all restricted-tender facts for this tenant)
//   - ae:realm:{issuer} entries whose stored tenant equals this tenant
//   - The matching L1 entries in RestrictedTenderSet and RealmMap
//
// Both extended evictions are best-effort: a failure is logged as a warning
// but does not return an error (degradation is bounded — stale ae:realm /
// ae:restricted facts for an offboarded tenant persist until the next pod
// restart or a manual flush, not indefinitely after the next deploy).
func (inv *Invalidator) HandleTenantOffboarded(ctx context.Context, tenant string) error {
	if err := inv.cache.EvictTenantContext(ctx, tenant); err != nil {
		return fmt.Errorf("evict ae:tenant: %w", err)
	}
	if err := inv.cache.EvictRestrictedByTenant(ctx, tenant); err != nil {
		inv.log.Warn("best-effort ae:restricted eviction failed on TenantOffboarded",
			map[string]interface{}{"error": err.Error()})
		inv.recorder.ObserveEvictionError("tenant_offboarded_restricted")
	}
	inv.restricted.ClearByTenant(tenant)
	if err := inv.cache.EvictRealmsByTenant(ctx, tenant); err != nil {
		inv.log.Warn("best-effort ae:realm eviction failed on TenantOffboarded",
			map[string]interface{}{"error": err.Error()})
		inv.recorder.ObserveEvictionError("tenant_offboarded_realm")
	}
	inv.realmMap.DeleteByTenant(tenant)
	return nil
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
// Both RP-2 (direct-paid signup) and RP-3 (trial→dedicated conversion) always
// co-emit TenantRealmReady alongside TenantConverted. This handler must still
// be wired because TenantRealmReady MUST be in the tenant-authz-q SNS filter —
// omitting it leaves this handler dead and breaks any future RP path that may
// emit TenantRealmReady independently of TenantConverted.
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

// TenderAccessGrantedPayload is tender-authz-q's decoded payload for
// TenderAccessGranted (§16 AE-TND-G1): the user and tender whose ACL entry
// must be evicted immediately so the next request fetches fresh data from
// iam-tender-acl instead of serving a stale Deny for up to 15 s.
type TenderAccessGrantedPayload struct {
	UserID   string `json:"user_id"`
	TenderID string `json:"tender_id"`
}

// HandleTenderAccessGranted evicts ae:tender_acl:{tenant}:{tender_id}:{user_id}
// immediately on receipt of TenderAccessGranted (§16 AE-TND-G1). Unlike the
// best-effort SCAN used for MembershipRevoked/UserDeleted, all three key
// components are known here, so this is a targeted single-key DEL. The error
// is returned (not swallowed) so the platform retries if Valkey is temporarily
// unreachable — leaving the error unhandled would keep the user denied until
// the 15 s TTL expires.
func (inv *Invalidator) HandleTenderAccessGranted(ctx context.Context, tenant string, p TenderAccessGrantedPayload) error {
	if tenant == "" {
		return fmt.Errorf("TenderAccessGranted envelope missing tenant_id: producer schema drift or malformed envelope")
	}
	if p.UserID == "" {
		return fmt.Errorf("TenderAccessGranted payload missing user_id: producer schema drift or malformed envelope")
	}
	if p.TenderID == "" {
		return fmt.Errorf("TenderAccessGranted payload missing tender_id: producer schema drift or malformed envelope")
	}
	if err := inv.cache.EvictTenderACL(ctx, tenant, p.TenderID, p.UserID); err != nil {
		// No ObserveEvictionError here: unlike the best-effort handlers
		// (MembershipRevoked, UserDeleted, TenantOffboarded) that swallow the
		// error and can only increment once per delivery, this handler returns
		// the error so the platform retries up to maxReceiveCount times. Firing
		// the counter on each attempt would make the label count retries rather
		// than missed evictions — inconsistent with every other label. The
		// returned error is observable through the consumer platform logs and
		// the DLQ depth alarm.
		inv.log.Warn("evict ae:tender_acl failed on TenderAccessGranted", map[string]interface{}{
			"error": err.Error(), "tenant": tenant, "tender_id": p.TenderID, "user_id": p.UserID,
		})
		return fmt.Errorf("evict ae:tender_acl: %w", err)
	}
	// Structured signal ops can grep for to confirm C1/TND-Q2 is live and
	// events are flowing (§16 AE-TND-G1). The runbook's C1/TND-Q2 verification
	// step references this log line.
	inv.log.Info("tender_acl_evicted", map[string]interface{}{
		"tenant": tenant, "tender_id": p.TenderID, "user_id": p.UserID,
	})
	return nil
}

// HandleTenderRestricted flips the restricted-tender fact (L1 + shared
// Valkey). Not a cache eviction (§5).
//
// An empty TenantID or TenderID means the producer payload is malformed or
// the field was renamed — writing ae:restricted:: would be a silent
// correctness bug (the key would never match a real-tenant IsRestricted
// lookup), so we return an error and let the platform retry/DLQ.
func (inv *Invalidator) HandleTenderRestricted(ctx context.Context, tenant string, p TenderRestrictedPayload) error {
	if tenant == "" {
		return fmt.Errorf("TenderRestricted envelope missing tenant_id: producer schema drift or malformed envelope")
	}
	if p.TenderID == "" {
		return fmt.Errorf("TenderRestricted payload missing tender_id: producer schema drift or malformed envelope")
	}
	if err := inv.restricted.MarkRestricted(ctx, tenant, p.TenderID); err != nil {
		return fmt.Errorf("persist restricted tender: %w", err)
	}
	return nil
}

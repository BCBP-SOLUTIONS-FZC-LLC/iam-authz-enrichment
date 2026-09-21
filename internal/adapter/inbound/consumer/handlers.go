package consumer

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/events"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
)

// Each handler below is a plain events.Handler, factored out from its
// NewXConsumer builder so it's directly unit-testable (call it with a
// hand-built events.Envelope) without any SQS/LocalStack machinery.

// membershipHandler implements membership-authz-q (§5):
// DepartmentMembershipGranted/Revoked/LevelChanged, TenantRoleGranted/Revoked,
// and MembershipRevoked — Org & Membership's per-user removal cascade signal
// (LLD §16 AE-20), the only event that fires on a whole-membership removal
// (per-grant rows are left inert rather than individually revoked), so it
// gets a wider eviction than the other five (also clears ae:tender_acl).
func membershipHandler(deps Deps) events.Handler {
	return func(ctx context.Context, env events.Envelope[json.RawMessage]) error {
		switch env.Type {
		case "DepartmentMembershipGranted", "DepartmentMembershipRevoked", "DepartmentMembershipLevelChanged",
			"TenantRoleGranted", "TenantRoleRevoked", "MembershipRevoked":
		default:
			return nil
		}
		var p usecase.MembershipEventPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return fmt.Errorf("decode %s payload: %w", env.Type, err)
		}
		if env.Type == "MembershipRevoked" {
			return deps.Invalidator.HandleMembershipRevoked(ctx, env.TenantID, p)
		}
		return deps.Invalidator.HandleMembershipEvent(ctx, env.TenantID, p)
	}
}

// NewMembershipConsumer builds the membership-authz-q consumer.
func NewMembershipConsumer(queueURL string, deps Deps, opts ...events.ConsumerOption) (events.Consumer, error) {
	return buildConsumer(queueURL, "membership-authz-q", deps, membershipHandler(deps), opts...)
}

// userHandler implements user-authz-q (§5): UserUpdated (email changes
// only — filtered via UserEventPayload.IsEmailChange, not an SNS attribute
// filter), UserAvailabilityChanged, UserDeleted.
func userHandler(deps Deps) events.Handler {
	return func(ctx context.Context, env events.Envelope[json.RawMessage]) error {
		switch env.Type {
		case "UserUpdated", "UserAvailabilityChanged", "UserDeleted":
		default:
			return nil
		}
		var p usecase.UserEventPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return fmt.Errorf("decode %s payload: %w", env.Type, err)
		}
		switch env.Type {
		case "UserUpdated":
			return deps.Invalidator.HandleUserUpdated(ctx, env.TenantID, p)
		case "UserAvailabilityChanged":
			return deps.Invalidator.HandleUserAvailabilityChanged(ctx, env.TenantID, p)
		default: // UserDeleted — the only remaining case reachable past the guard above
			return deps.Invalidator.HandleUserDeleted(ctx, env.TenantID, p)
		}
	}
}

// NewUserConsumer builds the user-authz-q consumer.
func NewUserConsumer(queueURL string, deps Deps, opts ...events.ConsumerOption) (events.Consumer, error) {
	return buildConsumer(queueURL, "user-authz-q", deps, userHandler(deps), opts...)
}

// billingHandler implements billing-authz-q (§5): TenantPlanChanged,
// TenantSubscriptionCancelled, TenantReactivated — all three evict the same
// single tenant-scoped key, so no payload decoding is needed beyond the
// envelope's own tenant_id.
func billingHandler(deps Deps) events.Handler {
	return func(ctx context.Context, env events.Envelope[json.RawMessage]) error {
		switch env.Type {
		case "TenantPlanChanged", "TenantSubscriptionCancelled", "TenantReactivated":
		default:
			return nil
		}
		return deps.Invalidator.HandleBillingEvent(ctx, env.TenantID)
	}
}

// NewBillingConsumer builds the billing-authz-q consumer.
func NewBillingConsumer(queueURL string, deps Deps, opts ...events.ConsumerOption) (events.Consumer, error) {
	return buildConsumer(queueURL, "billing-authz-q", deps, billingHandler(deps), opts...)
}

// tenantHandler implements tenant-authz-q (§5): TenantConverted (evicts +
// refreshes the realm map) and TenantRealmReady (refreshes the realm map
// only — no ae:ctx eviction). Both must be wired: a direct-paid-signup
// tenant fires only TenantRealmReady.
func tenantHandler(deps Deps) events.Handler {
	return func(ctx context.Context, env events.Envelope[json.RawMessage]) error {
		var p usecase.TenantRealmEventPayload
		switch env.Type {
		case "TenantConverted", "TenantRealmReady":
			if err := json.Unmarshal(env.Payload, &p); err != nil {
				return fmt.Errorf("decode %s payload: %w", env.Type, err)
			}
		default:
			return nil
		}
		switch env.Type {
		case "TenantConverted":
			return deps.Invalidator.HandleTenantConverted(ctx, env.TenantID, p)
		case "TenantRealmReady":
			deps.Invalidator.HandleTenantRealmReady(env.TenantID, p)
		}
		return nil
	}
}

// NewTenantConsumer builds the tenant-authz-q consumer.
func NewTenantConsumer(queueURL string, deps Deps, opts ...events.ConsumerOption) (events.Consumer, error) {
	return buildConsumer(queueURL, "tenant-authz-q", deps, tenantHandler(deps), opts...)
}

// tenderHandler implements tender-authz-q (§5): TenderRestricted — flips an
// in-memory fact, not a cache eviction.
func tenderHandler(deps Deps) events.Handler {
	return func(_ context.Context, env events.Envelope[json.RawMessage]) error {
		if env.Type != "TenderRestricted" {
			return nil
		}
		var p usecase.TenderRestrictedPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return fmt.Errorf("decode %s payload: %w", env.Type, err)
		}
		deps.Invalidator.HandleTenderRestricted(env.TenantID, p)
		return nil
	}
}

// NewTenderConsumer builds the tender-authz-q consumer.
func NewTenderConsumer(queueURL string, deps Deps, opts ...events.ConsumerOption) (events.Consumer, error) {
	return buildConsumer(queueURL, "tender-authz-q", deps, tenderHandler(deps), opts...)
}

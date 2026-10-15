// Package usecase orchestrates the check/invalidate/tenant-resolution flows.
// It depends only on internal/domain and the interfaces declared here — the
// outbound adapters (valkey, orgmembership) implement these interfaces, and
// the inbound adapters (grpc, consumer) call into this package. Nothing in
// this package imports an adapter package directly.
package usecase

import (
	"context"
	"time"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// Cache is the port this layer needs from the Valkey outbound adapter.
type Cache interface {
	GetMembershipContext(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.CacheResult, error)
	SetMembershipContext(ctx context.Context, tenant, user string, v domain.MembershipContext) error
	EvictMembershipContext(ctx context.Context, tenant, user string) error

	GetTenantContext(ctx context.Context, tenant string) (domain.TenantContext, domain.CacheResult, error)
	SetTenantContext(ctx context.Context, tenant string, v domain.TenantContext) error
	EvictTenantContext(ctx context.Context, tenant string) error

	GetTenderACL(ctx context.Context, tenant, tender, user string) (domain.TenderACL, bool, error)
	SetTenderACL(ctx context.Context, tenant, tender, user string, v domain.TenderACL) error
	EvictTenderACLForUser(ctx context.Context, tenant, user string) error

	GetNegative(ctx context.Context, tenant, user string) (bool, error)
	SetNegative(ctx context.Context, tenant, user string) error
	EvictNegative(ctx context.Context, tenant, user string) error

	// Shared per-replica facts: competing SQS consumers deliver each
	// TenantConverted / TenantRealmReady / TenderRestricted to one pod.
	// These keys are how every other replica observes the same fact.
	GetRealm(ctx context.Context, realm string) (tenant string, ok bool, err error)
	SetRealm(ctx context.Context, realm, tenant string) error
	GetRestricted(ctx context.Context, tenant, tender string) (bool, error)
	SetRestricted(ctx context.Context, tenant, tender string) error
}

// OrgMembershipClient is the port this layer needs from the sibling Org &
// Membership service (§6).
type OrgMembershipClient interface {
	GetMemberships(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, error)
	GetTenderACL(ctx context.Context, tenant, tenderID, user string) (domain.TenderACL, error)
	GetMFAFreshness(ctx context.Context, tenant string) (time.Duration, error)
}

// Recorder is the metrics port (§10). A no-op implementation is used in
// tests that don't care about metrics; internal/adapter/outbound/metrics
// provides the Prometheus-backed implementation wired in cmd/server.
type Recorder interface {
	ObserveDecision(reason domain.DenyReason, allowed bool)
	ObserveCacheHit(hit bool)
	ObserveNegativeCacheHit(hit bool)
	ObserveStaleIfErrorServed()
	ObserveSingleflightCoalesced()
	ObserveI8Latency(d time.Duration)
	ObserveI12Latency(d time.Duration)
	ObserveI14Latency(d time.Duration)
	ObserveDecisionLatency(d time.Duration)
	// ObserveResidencyUnknown increments the counter for Allow decisions where
	// Core returned an unrecognised residency_mode (empty or unknown value),
	// triggering the fail-safe "strict" default (LLD §16 AE-38, CD-37).
	ObserveResidencyUnknown()
}

// NoopRecorder implements Recorder with no side effects.
type NoopRecorder struct{}

func (NoopRecorder) ObserveDecision(domain.DenyReason, bool) {}
func (NoopRecorder) ObserveCacheHit(bool)                    {}
func (NoopRecorder) ObserveNegativeCacheHit(bool)            {}
func (NoopRecorder) ObserveStaleIfErrorServed()              {}
func (NoopRecorder) ObserveSingleflightCoalesced()           {}
func (NoopRecorder) ObserveI8Latency(time.Duration)          {}
func (NoopRecorder) ObserveI12Latency(time.Duration)         {}
func (NoopRecorder) ObserveI14Latency(time.Duration)         {}
func (NoopRecorder) ObserveDecisionLatency(time.Duration)    {}
func (NoopRecorder) ObserveResidencyUnknown()                {}

// Logger mirrors platform-gincommon's port.Logger method set structurally —
// that type lives in an internal package we cannot import directly, so every
// IAM service declares its own local interface with the same shape (same
// convention as iam-user-profile's consumer package).
type Logger interface {
	Debug(msg string, fields map[string]interface{})
	Info(msg string, fields map[string]interface{})
	Warn(msg string, fields map[string]interface{})
	Error(msg string, fields map[string]interface{})
}

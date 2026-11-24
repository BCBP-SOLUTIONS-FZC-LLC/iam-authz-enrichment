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
	// Write guard (§16 AE-51): every Set* that caches a sibling's answer
	// writes only if a generation token still equals gen, read before the
	// sibling call. Every matching Evict* replaces the token, so an eviction
	// that lands while I-8 / TAC-4 is answering always wins.
	//   - (tenant,user) token, GetSubjectGen: SetMembershipContext,
	//     SetNegative, SetTenderACL; replaced by EvictMembershipContext,
	//     EvictNegative, EvictTenderACL, EvictTenderACLForUser.
	//   - tenant token, GetTenantGen: SetTenantContext; replaced by
	//     EvictTenantContext.
	// Tokens are never empty; a token that cannot be read means no write.
	SetMembershipContext(ctx context.Context, tenant, user string, v domain.MembershipContext, gen string) error
	EvictMembershipContext(ctx context.Context, tenant, user string) error

	GetTenantContext(ctx context.Context, tenant string) (domain.TenantContext, domain.CacheResult, error)
	GetTenantGen(ctx context.Context, tenant string) (string, error)
	SetTenantContext(ctx context.Context, tenant string, v domain.TenantContext, gen string) error
	EvictTenantContext(ctx context.Context, tenant string) error

	GetTenderACL(ctx context.Context, tenant, tender, user string) (domain.TenderACL, bool, error)
	SetTenderACL(ctx context.Context, tenant, tender, user string, v domain.TenderACL, gen string) error
	// EvictTenderACL deletes the single ae:tender_acl:{tenant}:{tender}:{user}
	// entry when all three key components are known (TenderAccessGranted, §16 AE-TND-G1).
	EvictTenderACL(ctx context.Context, tenant, tender, user string) error
	EvictTenderACLForUser(ctx context.Context, tenant, user string) error

	// GetNegative returns the deny reason cached in ae:neg:{tenant}:{user},
	// or "" when there is none. SetNegative caches reason for the fixed
	// negative TTL (§4.3): DenyUnresolvableSubject or DenyMemberSuspended.
	// Any other stored value reads back as DenyUnresolvableSubject
	// (domain.NegativeCacheReason).
	GetNegative(ctx context.Context, tenant, user string) (domain.DenyReason, error)
	GetSubjectGen(ctx context.Context, tenant, user string) (string, error)
	SetNegative(ctx context.Context, tenant, user string, reason domain.DenyReason, gen string) error
	EvictNegative(ctx context.Context, tenant, user string) error

	// Shared per-replica facts: competing SQS consumers deliver each
	// TenantConverted / TenantRealmReady / TenderRestricted to one pod.
	// These keys are how every other replica observes the same fact.
	GetRealm(ctx context.Context, realm string) (tenant string, ok bool, err error)
	SetRealm(ctx context.Context, realm, tenant string) error
	GetRestricted(ctx context.Context, tenant, tender string) (bool, error)
	SetRestricted(ctx context.Context, tenant, tender string) error

	// EvictRestrictedByTenant best-effort-deletes every ae:restricted entry for
	// a tenant (TenantOffboarded full-cleanup — ae:restricted has no TTL).
	EvictRestrictedByTenant(ctx context.Context, tenant string) error
	// EvictRealmsByTenant best-effort-deletes every ae:realm entry whose stored
	// value equals tenant (TenantOffboarded — ae:realm has no TTL).
	EvictRealmsByTenant(ctx context.Context, tenant string) error
}

// OrgMembershipClient is the port this layer needs from the sibling Org &
// Membership service (§6) and iam-tender-acl (ADR-0007 Wave 3 Phase 4).
// It covers only the three calls the §3.1 Check() precedence chain makes:
// I-8 (membership rebuild), TAC-4 (tender-ACL overlay), and I-14 (MFA
// freshness). The batch TAC-5 call lives on BatchTenderACLClient below.
type OrgMembershipClient interface {
	GetMemberships(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, error)
	GetTenderACL(ctx context.Context, tenant, tenderID, user string) (domain.TenderACL, error)
	GetMFAFreshness(ctx context.Context, tenant string) (time.Duration, error)
}

// BatchTenderACLClient is the narrower port for the TAC-5 batch check
// (iam-tender-acl §8.4 / TAC-D14): a single POST replacing N individual
// TAC-4 calls for dashboard-read paths (AE-30) that need many (tender, user)
// pairs in one tenant. Callers must chunk requests > 50 items — iam-tender-acl
// enforces that cap and returns 422 on violation (mapped to ErrUnavailable).
//
// Kept separate from OrgMembershipClient so every existing test fake for the
// §3.1 Check() chain does not need to implement a method it never exercises.
// Wire this interface at the call site that actually invokes GetBatchTenderACL,
// not at NewChecker.
type BatchTenderACLClient interface {
	GetBatchTenderACL(ctx context.Context, tenant string, items []domain.BatchTenderACLItem) ([]domain.BatchTenderACLResult, error)
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
	// triggering the fail-safe "strict" default (LLD §16 AE-40, CD-37).
	ObserveResidencyUnknown()
	// ObserveTACDependencyError increments the TAC-4 error counter when
	// resolveTenderACL returns an error — distinguishing a real iam-tender-acl
	// outage from legitimate insufficient-access denials in Prometheus.
	ObserveTACDependencyError()
	// ObserveEvictionError increments the best-effort eviction-failure counter
	// for the named event (e.g. "membership_revoked", "user_deleted") when
	// EvictTenderACLForUser errors, making systematic SCAN failures alertable.
	ObserveEvictionError(event string)
	// ObserveCacheGuardError counts write-guard failures (§16 AE-51): op is
	// "gen_read" (a token could not be read, so the matching cache write was
	// skipped) or "guarded_write" (a guarded cache write failed). A sustained
	// rate means caching has quietly stopped and every miss reaches the
	// sibling — e.g. a Valkey ACL or proxy that refuses Lua scripts.
	ObserveCacheGuardError(op string)
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
func (NoopRecorder) ObserveTACDependencyError()              {}
func (NoopRecorder) ObserveEvictionError(string)             {}
func (NoopRecorder) ObserveCacheGuardError(string)           {}

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

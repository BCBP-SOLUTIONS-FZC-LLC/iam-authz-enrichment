// Package valkey is the outbound cache adapter (LLD §4). It owns Valkey key
// construction and TTL/jitter policy; callers never build keys themselves.
package valkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// entry is the envelope stored for jittered-TTL keys (ae:ctx, ae:tenant).
// SoftTTL is the per-write jittered duration (§4.1's "60s ± 6s") used to
// compute freshness independently of the physical Redis TTL, which is set
// longer (SoftTTL + stale-if-error grace) so the same key can serve both the
// normal read-through path and the §7 stale-if-error fallback without a
// second shadow key.
type entry[T any] struct {
	Value     T             `json:"value"`
	FetchedAt time.Time     `json:"fetched_at"`
	SoftTTL   time.Duration `json:"soft_ttl"`
}

// Cache is the Valkey-backed outbound adapter. Config for TTL/jitter/timeouts
// is injected at construction — this package holds no config defaults of its
// own beyond what New receives.
type Cache struct {
	client             *redis.Client
	ctxTTL             time.Duration
	ctxJitter          time.Duration
	tenderACLTTL       time.Duration
	negativeTTL        time.Duration
	processedTTL       time.Duration
	staleIfErrorMaxAge time.Duration
}

// Config configures a new Cache.
type Config struct {
	Addr               string
	DialTimeout        time.Duration
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	CtxTTL             time.Duration
	CtxJitter          time.Duration
	TenderACLTTL       time.Duration
	NegativeTTL        time.Duration
	ProcessedTTL       time.Duration
	StaleIfErrorMaxAge time.Duration
}

// New builds a Cache. addr is parsed via redis.ParseURL when it looks like a
// URL (rediss://... for TLS in transit, per §1), falling back to a plain
// host:port Addr — same pattern as iam-user-profile's cache adapter.
func New(cfg Config) *Cache {
	opts, err := redis.ParseURL(cfg.Addr)
	if err != nil {
		opts = &redis.Options{Addr: cfg.Addr}
	}
	if cfg.DialTimeout > 0 {
		opts.DialTimeout = cfg.DialTimeout
	}
	if cfg.ReadTimeout > 0 {
		opts.ReadTimeout = cfg.ReadTimeout
	}
	if cfg.WriteTimeout > 0 {
		opts.WriteTimeout = cfg.WriteTimeout
	}
	return &Cache{
		client:             redis.NewClient(opts),
		ctxTTL:             cfg.CtxTTL,
		ctxJitter:          cfg.CtxJitter,
		tenderACLTTL:       cfg.TenderACLTTL,
		negativeTTL:        cfg.NegativeTTL,
		processedTTL:       cfg.ProcessedTTL,
		staleIfErrorMaxAge: cfg.StaleIfErrorMaxAge,
	}
}

// jitteredTTL returns base ± jitter, uniformly distributed, per §4.1's
// explicit instruction to desynchronize expiry across replicas ("don't use a
// flat 60s").
func jitteredTTL(base, jitter time.Duration) time.Duration {
	if jitter <= 0 {
		return base
	}
	delta := time.Duration(rand.Int63n(int64(2*jitter+1))) - jitter
	return base + delta
}

func (c *Cache) setJittered(ctx context.Context, key string, value any, base, jitter, grace time.Duration) error {
	soft := jitteredTTL(base, jitter)
	e := entry[any]{Value: value, FetchedAt: time.Now(), SoftTTL: soft}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal cache entry: %w", err)
	}
	physicalTTL := soft + grace
	return c.client.Set(ctx, key, b, physicalTTL).Err()
}

func getJittered[T any](ctx context.Context, c *Cache, key string) (T, domain.CacheResult, error) {
	var zero T
	raw, err := c.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return zero, domain.CacheMiss, nil
	}
	if err != nil {
		return zero, domain.CacheMiss, err
	}
	var e entry[T]
	if err := json.Unmarshal(raw, &e); err != nil {
		return zero, domain.CacheMiss, fmt.Errorf("unmarshal cache entry %s: %w", key, err)
	}
	if time.Since(e.FetchedAt) <= e.SoftTTL {
		return e.Value, domain.CacheFresh, nil
	}
	return e.Value, domain.CacheStale, nil
}

// GetMembershipContext reads ae:ctx:{tenant}:{user}.
func (c *Cache) GetMembershipContext(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.CacheResult, error) {
	return getJittered[domain.MembershipContext](ctx, c, ctxKey(tenant, user))
}

// SetMembershipContext writes ae:ctx:{tenant}:{user} — never includes
// mfa_freshness_seconds; MembershipContext's type has no field for it (§4.4).
func (c *Cache) SetMembershipContext(ctx context.Context, tenant, user string, v domain.MembershipContext) error {
	return c.setJittered(ctx, ctxKey(tenant, user), v, c.ctxTTL, c.ctxJitter, c.staleIfErrorMaxAge)
}

// EvictMembershipContext deletes ae:ctx:{tenant}:{user} — the single-key
// eviction used by every §5 membership/user event.
func (c *Cache) EvictMembershipContext(ctx context.Context, tenant, user string) error {
	return c.client.Del(ctx, ctxKey(tenant, user)).Err()
}

// GetTenantContext reads ae:tenant:{tenant}.
func (c *Cache) GetTenantContext(ctx context.Context, tenant string) (domain.TenantContext, domain.CacheResult, error) {
	return getJittered[domain.TenantContext](ctx, c, tenantKey(tenant))
}

// SetTenantContext writes ae:tenant:{tenant}.
func (c *Cache) SetTenantContext(ctx context.Context, tenant string, v domain.TenantContext) error {
	return c.setJittered(ctx, tenantKey(tenant), v, c.ctxTTL, c.ctxJitter, c.staleIfErrorMaxAge)
}

// EvictTenantContext deletes ae:tenant:{tenant} — the single-key eviction
// used by every §5 billing/tenant-conversion event. This is exactly the
// eviction §4.1 requires tenant-wide events to use instead of a SCAN.
func (c *Cache) EvictTenantContext(ctx context.Context, tenant string) error {
	return c.client.Del(ctx, tenantKey(tenant)).Err()
}

// GetTenderACL reads ae:tender_acl:{tenant}:{tender}:{user}. No staleness
// concept here — §7 gives this overlay its own independent fail-closed rule,
// unrelated to ae:ctx's stale-if-error.
func (c *Cache) GetTenderACL(ctx context.Context, tenant, tender, user string) (domain.TenderACL, bool, error) {
	var v domain.TenderACL
	raw, err := c.client.Get(ctx, tenderACLKey(tenant, tender, user)).Bytes()
	if errors.Is(err, redis.Nil) {
		return v, false, nil
	}
	if err != nil {
		return v, false, err
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, false, err
	}
	return v, true, nil
}

// SetTenderACL writes ae:tender_acl:{tenant}:{tender}:{user} with the fixed
// 15s TTL (§4.1 — half the sibling service's own 30s TTL on the same data).
func (c *Cache) SetTenderACL(ctx context.Context, tenant, tender, user string, v domain.TenderACL) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, tenderACLKey(tenant, tender, user), b, c.tenderACLTTL).Err()
}

// EvictTenderACLForUser best-effort-deletes every ae:tender_acl entry for
// (tenant, user) across all tenders (§5 UserDeleted). SCAN, not KEYS, to
// avoid blocking Valkey — this is explicitly a best-effort path, so a partial
// failure mid-scan is logged by the caller, not retried here.
func (c *Cache) EvictTenderACLForUser(ctx context.Context, tenant, user string) error {
	pattern := tenderACLUserPattern(tenant, user)
	var cursor uint64
	for {
		keys, next, err := c.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			if err := c.client.Del(ctx, keys...).Err(); err != nil {
				return err
			}
		}
		cursor = next
		if cursor == 0 {
			return nil
		}
	}
}

// GetNegative checks ae:neg:{tenant}:{user} — a cached "subject rebuild
// returned 404" sentinel (§4.3).
func (c *Cache) GetNegative(ctx context.Context, tenant, user string) (bool, error) {
	err := c.client.Get(ctx, negativeKey(tenant, user)).Err()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// SetNegative writes the ae:neg sentinel with its fixed 5s TTL.
func (c *Cache) SetNegative(ctx context.Context, tenant, user string) error {
	return c.client.Set(ctx, negativeKey(tenant, user), "1", c.negativeTTL).Err()
}

// EvictNegative deletes ae:neg:{tenant}:{user} — wired into every grant event
// so a freshly-granted user is never held to the full 5s negative TTL (§4.3).
func (c *Cache) EvictNegative(ctx context.Context, tenant, user string) error {
	return c.client.Del(ctx, negativeKey(tenant, user)).Err()
}

// MarkProcessed implements consumer idempotency (§5) via SET NX — the
// functional equivalent of Postgres's INSERT ... ON CONFLICT DO NOTHING for
// a service with no database. Returns true the first time a given eventID is
// seen; false (and no error) on every subsequent delivery.
func (c *Cache) MarkProcessed(ctx context.Context, eventID string) (bool, error) {
	ok, err := c.client.SetNX(ctx, processedKey(eventID), "1", c.processedTTL).Result()
	if err != nil {
		return false, err
	}
	return ok, nil
}

// EvictProcessed deletes ae:processed:{eventID} — used when a handler fails
// after MarkProcessed already claimed the ID, so a redelivery gets a real
// retry instead of a false-positive dedup skip.
func (c *Cache) EvictProcessed(ctx context.Context, eventID string) error {
	return c.client.Del(ctx, processedKey(eventID)).Err()
}

// Health pings Valkey.
func (c *Cache) Health(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// Close closes the underlying client.
func (c *Cache) Close() error {
	return c.client.Close()
}

// Package valkey is the outbound cache adapter (LLD §4). It owns Valkey key
// construction and TTL/jitter policy; callers never build keys themselves.
package valkey

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand"
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
	delta := time.Duration(mrand.Int63n(int64(2*jitter+1))) - jitter
	return base + delta
}

// setJittered writes a jittered-TTL envelope through setIfGen: only while the
// guard's token is unchanged (§16 AE-51).
func (c *Cache) setJittered(ctx context.Context, key string, value any, base, jitter, grace time.Duration, guard genGuard) error {
	soft := jitteredTTL(base, jitter)
	e := entry[any]{Value: value, FetchedAt: time.Now(), SoftTTL: soft}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal cache entry: %w", err)
	}
	return c.setIfGen(ctx, key, guard.key, b, soft+grace, guard.token)
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
	if json.Unmarshal(raw, &e) != nil {
		// An entry that cannot be decoded (an old or foreign envelope) is
		// dropped and read as a miss. Returning an error instead would mark
		// Valkey unreachable on every request for this key, so the entry
		// would never be overwritten and every request would reach I-8
		// until its physical TTL ran out (§16 AE-51). The DEL is best
		// effort: if it fails, the next guarded write replaces the entry.
		_ = c.client.Del(ctx, key).Err()
		return zero, domain.CacheMiss, nil //nolint:nilerr // a decode failure is a miss by design (see above)
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
// The write happens only if the ae:gen token still equals gen — no
// EvictMembershipContext / EvictNegative ran since the caller read it before
// the I-8 call — so an in-flight rebuild cannot undo a membership event
// (§16 AE-51). A skipped write is not an error.
func (c *Cache) SetMembershipContext(ctx context.Context, tenant, user string, v domain.MembershipContext, gen string) error {
	return c.setJittered(ctx, ctxKey(tenant, user), v, c.ctxTTL, c.ctxJitter, c.staleIfErrorMaxAge,
		genGuard{key: subjectGenKey(tenant, user), token: gen})
}

// EvictMembershipContext deletes ae:ctx:{tenant}:{user} — the single-key
// eviction used by every §5 membership/user event — and replaces the ae:gen
// token in the same MULTI/EXEC (§16 AE-51).
func (c *Cache) EvictMembershipContext(ctx context.Context, tenant, user string) error {
	return c.delAndReplaceGen(ctx, ctxKey(tenant, user), subjectGenKey(tenant, user))
}

// GetTenantContext reads ae:tenant:{tenant} and normalises ResidencyMode so
// that all callers receive a canonical ("standard" | "strict") value even
// when the cached entry was written before CD-37 or by a pre-upgrade Core.
func (c *Cache) GetTenantContext(ctx context.Context, tenant string) (domain.TenantContext, domain.CacheResult, error) {
	tc, result, err := getJittered[domain.TenantContext](ctx, c, tenantKey(tenant))
	if result != domain.CacheMiss {
		tc.NormaliseResidencyMode()
	}
	return tc, result, err
}

// SetTenantContext writes ae:tenant:{tenant}, only while the tenant's
// ae:tgen token still equals gen (read with GetTenantGen before the I-8
// call), so a tenant event that evicts while I-8 is answering — a
// cancellation turning on read_only, say — is never undone (§16 AE-51).
func (c *Cache) SetTenantContext(ctx context.Context, tenant string, v domain.TenantContext, gen string) error {
	return c.setJittered(ctx, tenantKey(tenant), v, c.ctxTTL, c.ctxJitter, c.staleIfErrorMaxAge,
		genGuard{key: tenantGenKey(tenant), token: gen})
}

// EvictTenantContext deletes ae:tenant:{tenant} — the single-key eviction
// used by every §5 billing/tenant-conversion event. This is exactly the
// eviction §4.1 requires tenant-wide events to use instead of a SCAN. It
// replaces the ae:tgen token in the same MULTI/EXEC.
func (c *Cache) EvictTenantContext(ctx context.Context, tenant string) error {
	return c.delAndReplaceGen(ctx, tenantKey(tenant), tenantGenKey(tenant))
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
// 15s TTL (§4.1 — half the sibling service's own 30s TTL on the same data),
// only while the (tenant,user) ae:gen token still equals gen (read before
// the TAC-4 call), so a tender-access event is never undone (§16 AE-51).
func (c *Cache) SetTenderACL(ctx context.Context, tenant, tender, user string, v domain.TenderACL, gen string) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.setIfGen(ctx, tenderACLKey(tenant, tender, user), subjectGenKey(tenant, user), b, c.tenderACLTTL, gen)
}

// EvictTenderACL deletes the single ae:tender_acl:{tenant}:{tender}:{user}
// entry when all three key components are known (TenderAccessGranted — §16
// AE-TND-G1), replacing the (tenant,user) ae:gen token in the same
// MULTI/EXEC. A plain DEL, not SCAN — fast and non-blocking.
func (c *Cache) EvictTenderACL(ctx context.Context, tenant, tender, user string) error {
	return c.delAndReplaceGen(ctx, tenderACLKey(tenant, tender, user), subjectGenKey(tenant, user))
}

// EvictTenderACLForUser best-effort-deletes every ae:tender_acl entry for
// (tenant, user) across all tenders (§5 UserDeleted). SCAN, not KEYS, to
// avoid blocking Valkey — this is explicitly a best-effort path, so a partial
// failure mid-scan is logged by the caller, not retried here.
//
// The (tenant,user) ae:gen token is replaced first, before any DEL: a TAC-4
// rebuild that read the old token then cannot write back an entry the scan
// has already deleted (§16 AE-51).
func (c *Cache) EvictTenderACLForUser(ctx context.Context, tenant, user string) error {
	pattern := tenderACLUserPattern(tenant, user)
	var cursor uint64
	for {
		keys, next, err := c.scanTenderACL(ctx, tenant, user, pattern, cursor)
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

// scanTenderACL runs one SCAN page for EvictTenderACLForUser, with the
// (tenant,user) token SET ahead of it in the same pipeline, so the token is
// replaced before anything is deleted. Replacing it again on later pages is
// harmless: a rebuild that reads a newer token started after the event.
func (c *Cache) scanTenderACL(ctx context.Context, tenant, user, pattern string, cursor uint64) ([]string, uint64, error) {
	var scan *redis.ScanCmd
	if _, err := c.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, subjectGenKey(tenant, user), rand.Text(), subjectGenTTL)
		scan = pipe.Scan(ctx, cursor, pattern, 100)
		return nil
	}); err != nil {
		return nil, 0, err
	}
	return scan.Result()
}

// EvictRestrictedByTenant best-effort-deletes every ae:restricted entry for a
// tenant (§5 TenantOffboarded). SCAN, not KEYS, to avoid blocking Valkey.
// Same best-effort posture as EvictTenderACLForUser.
func (c *Cache) EvictRestrictedByTenant(ctx context.Context, tenant string) error {
	pattern := restrictedTenantPattern(tenant)
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

// EvictRealmsByTenant deletes every ae:realm:{issuer} entry for a tenant and
// the ae:realm-by-tenant:{tenant} reverse-index Set in a single DEL (§5
// TenantOffboarded). Uses the reverse index written by SetRealm so the
// lookup is O(k) where k is the number of realms for this tenant, not O(n)
// where n is the total number of ae:realm keys across all tenants.
func (c *Cache) EvictRealmsByTenant(ctx context.Context, tenant string) error {
	reverseKey := realmByTenantKey(tenant)
	realms, err := c.client.SMembers(ctx, reverseKey).Result()
	if err != nil {
		return err
	}
	// Build the full DEL key list: every forward ae:realm:{issuer} plus the
	// reverse-index key itself.
	keysToDelete := make([]string, 0, len(realms)+1)
	for _, r := range realms {
		keysToDelete = append(keysToDelete, realmKey(r))
	}
	keysToDelete = append(keysToDelete, reverseKey)
	return c.client.Del(ctx, keysToDelete...).Err()
}

// GetNegative checks ae:neg:{tenant}:{user} — a cached "subject rebuild
// found no active member" sentinel (§4.3) — and returns the deny reason it
// holds, or "" when there is no entry. The value is the reason itself,
// read back through domain.NegativeCacheReason: DENY_MEMBER_SUSPENDED for a
// suspended member (§16 AE-51), DENY_UNRESOLVABLE_SUBJECT for anything else.
func (c *Cache) GetNegative(ctx context.Context, tenant, user string) (domain.DenyReason, error) {
	v, err := c.client.Get(ctx, negativeKey(tenant, user)).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return domain.NegativeCacheReason(v), nil
}

// LoadScripts loads the write-guard Lua scripts into Valkey. Call it at
// startup: a Valkey that refuses scripts (an ACL without @scripting, a proxy
// that blocks EVAL) would otherwise only show up as every guarded cache write
// being skipped (§16 AE-51).
func (c *Cache) LoadScripts(ctx context.Context) error {
	for _, s := range []*redis.Script{setIfGenScript, getOrCreateGenScript} {
		if err := s.Load(ctx, c.client).Err(); err != nil {
			return fmt.Errorf("load write-guard script: %w", err)
		}
	}
	return nil
}

// subjectGenTTL is how long an ae:gen token lives. A write is guarded by
// the token the rebuild read, which is never empty (GetSubjectGen creates
// one if needed), and tokens never repeat. So a token that expires, is
// replaced by an eviction, or is lost (maxmemory eviction, a failover) can
// only make a guarded write skip — never let a stale one through.
const subjectGenTTL = time.Hour

// genGuard names the ae:gen token a guarded write must still match.
type genGuard struct {
	key, token string
}

// setIfGenScript writes KEYS[1] = ARGV[1] with PX ARGV[2] only while the
// ae:gen token (KEYS[2]) exists and equals ARGV[3]. An empty ARGV[3] never
// writes.
var setIfGenScript = redis.NewScript(`
if ARGV[3] == '' then return 0 end
if redis.call('GET', KEYS[2]) ~= ARGV[3] then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return 1`)

func (c *Cache) setIfGen(ctx context.Context, key, genKey string, value any, ttl time.Duration, gen string) error {
	return setIfGenScript.Run(ctx, c.client, []string{key, genKey}, value, max(ttl.Milliseconds(), 1), gen).Err()
}

// getOrCreateGenScript returns the ae:gen token (KEYS[1]), first setting it
// to ARGV[1] with PX ARGV[2] if there is none.
var getOrCreateGenScript = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if v then return v end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return ARGV[1]`)

// delAndReplaceGen deletes key and replaces the genKey token with a new
// random one, atomically.
func (c *Cache) delAndReplaceGen(ctx context.Context, key, genKey string) error {
	_, err := c.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Del(ctx, key)
		pipe.Set(ctx, genKey, rand.Text(), subjectGenTTL)
		return nil
	})
	return err
}

// getGen returns the token at genKey, never empty: a plain GET, and only
// when there is no token the create script (a write). So a subject that
// keeps missing — a non-member in a retry loop — costs one GET per request
// once its token exists.
func (c *Cache) getGen(ctx context.Context, genKey string) (string, error) {
	v, err := c.client.Get(ctx, genKey).Result()
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, redis.Nil) {
		return "", err
	}
	return getOrCreateGenScript.Run(ctx, c.client, []string{genKey}, rand.Text(), subjectGenTTL.Milliseconds()).Text()
}

// GetSubjectGen returns the (tenant, user) ae:gen token, never empty. The
// checker reads it before an I-8 or TAC-4 call and hands it to the guarded
// SetMembershipContext / SetNegative / SetTenderACL (§16 AE-51).
func (c *Cache) GetSubjectGen(ctx context.Context, tenant, user string) (string, error) {
	return c.getGen(ctx, subjectGenKey(tenant, user))
}

// GetTenantGen returns the tenant's ae:tgen token, never empty, for the
// guarded SetTenantContext.
func (c *Cache) GetTenantGen(ctx context.Context, tenant string) (string, error) {
	return c.getGen(ctx, tenantGenKey(tenant))
}

// SetNegative writes the ae:neg sentinel, holding reason, with its fixed 5s
// TTL — but only if the ae:gen token still equals gen (see
// SetMembershipContext). The check and the write are one atomic script.
func (c *Cache) SetNegative(ctx context.Context, tenant, user string, reason domain.DenyReason, gen string) error {
	return c.setIfGen(ctx, negativeKey(tenant, user), subjectGenKey(tenant, user), string(reason), c.negativeTTL, gen)
}

// EvictNegative deletes ae:neg:{tenant}:{user} — wired into every grant event
// so a freshly-granted user is never held to the full 5s negative TTL (§4.3)
// — and replaces the ae:gen token in the same MULTI/EXEC (§16 AE-51).
func (c *Cache) EvictNegative(ctx context.Context, tenant, user string) error {
	return c.delAndReplaceGen(ctx, negativeKey(tenant, user), subjectGenKey(tenant, user))
}

// MarkProcessed implements the platform-events processed_events contract
// via SET NX — the functional equivalent of Postgres's INSERT ... ON
// CONFLICT DO NOTHING for a service with no database. Returns true the
// first time a given eventID is seen; false (and no error) on every
// subsequent delivery. consumer is accepted for port-parity with
// iam-org-membership's processed_events (event_id, consumer) key; this
// process has a single PE-1 identity so the Valkey key stays
// ae:processed:{event_id} (LLD AE-6 — no key migration on deploy).
func (c *Cache) MarkProcessed(ctx context.Context, _, eventID string) (bool, error) {
	ok, err := c.client.SetNX(ctx, processedKey(eventID), "1", c.processedTTL).Result()
	if err != nil {
		return false, err
	}
	return ok, nil
}

// EvictProcessed deletes ae:processed:{eventID} — used when a handler fails
// after MarkProcessed already claimed the ID, so a redelivery gets a real
// retry instead of a false-positive dedup skip.
func (c *Cache) EvictProcessed(ctx context.Context, _, eventID string) error {
	return c.client.Del(ctx, processedKey(eventID)).Err()
}

// GetRealm reads ae:realm:{issuer}. No TTL — a dedicated realm is not
// reassigned once provisioned (LLD EVT-6).
func (c *Cache) GetRealm(ctx context.Context, realm string) (string, bool, error) {
	s, err := c.client.Get(ctx, realmKey(realm)).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return s, true, nil
}

// SetRealm writes ae:realm:{issuer} (forward) and adds the issuer to the
// ae:realm-by-tenant:{tenant} reverse-index Set in a single MULTI/EXEC
// transaction so both writes are atomic — a partial failure (forward key
// written but SAdd not reached) would leave EvictRealmsByTenant unable to
// find and clean up the forward key on offboarding.
func (c *Cache) SetRealm(ctx context.Context, realm, tenant string) error {
	_, err := c.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, realmKey(realm), tenant, 0)
		pipe.SAdd(ctx, realmByTenantKey(tenant), realm)
		return nil
	})
	return err
}

// GetRestricted reports whether ae:restricted:{tenant}:{tender} exists.
func (c *Cache) GetRestricted(ctx context.Context, tenant, tender string) (bool, error) {
	n, err := c.client.Exists(ctx, restrictedFactKey(tenant, tender)).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// SetRestricted writes ae:restricted:{tenant}:{tender} with no TTL —
// TenderRestricted is monotonic (there is no unrestrict event).
func (c *Cache) SetRestricted(ctx context.Context, tenant, tender string) error {
	return c.client.Set(ctx, restrictedFactKey(tenant, tender), "1", 0).Err()
}

// Health pings Valkey.
func (c *Cache) Health(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// Close closes the underlying client.
func (c *Cache) Close() error {
	return c.client.Close()
}

// WithTimeouts returns a Cache over the same Valkey with the same TTL
// settings but its own connection pool and socket timeouts. cmd/server uses
// it for SQS event processing: the request path's single-digit-ms timeouts
// exist for the 15ms decision budget, but an eviction has no such budget, and
// failing one on a momentary blip delays it by a whole SQS visibility
// timeout (30s) — indefinitely wrong state for ae:restricted, which has no
// TTL. The returned Cache must be closed separately.
func (c *Cache) WithTimeouts(dial, read, write time.Duration) *Cache {
	opts := *c.client.Options()
	opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout = dial, read, write
	clone := *c
	clone.client = redis.NewClient(&opts)
	return &clone
}

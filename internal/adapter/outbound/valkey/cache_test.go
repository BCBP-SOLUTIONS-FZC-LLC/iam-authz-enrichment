package valkey

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// failDelHook makes DEL commands fail while leaving every other command
// (SCAN, GET, SET, ...) untouched — used to reach the branch where a SCAN
// succeeds but the subsequent DEL fails, which mr.Close() alone can't
// isolate since that fails every command from the very first one.
type failDelHook struct{}

func (failDelHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (failDelHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "del" {
			return errors.New("simulated DEL failure")
		}
		return next(ctx, cmd)
	}
}

func (failDelHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func newTestCache(t *testing.T, jitter time.Duration) (*Cache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	c := New(Config{
		Addr:               mr.Addr(),
		CtxTTL:             time.Hour,
		CtxJitter:          jitter,
		TenderACLTTL:       time.Hour,
		NegativeTTL:        time.Hour,
		ProcessedTTL:       time.Hour,
		StaleIfErrorMaxAge: time.Hour,
	})
	t.Cleanup(func() { _ = c.Close() })
	return c, mr
}

func TestNew_ParsesRedisURL(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	c := New(Config{Addr: "redis://" + mr.Addr()})
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Health(context.Background()))
}

func TestNew_FallsBackToPlainAddrOnParseFailure(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	// Not a valid redis:// URL, so redis.ParseURL fails and New falls back to
	// treating it as a plain host:port Addr.
	c := New(Config{Addr: mr.Addr(), DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second})
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Health(context.Background()))
}

func TestJitteredTTL(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 60*time.Second, jitteredTTL(60*time.Second, 0), "jitter<=0 returns base unchanged")

	base, jitter := 60*time.Second, 6*time.Second
	for i := 0; i < 50; i++ {
		got := jitteredTTL(base, jitter)
		assert.GreaterOrEqual(t, got, base-jitter)
		assert.LessOrEqual(t, got, base+jitter)
	}
}

func TestMembershipContext_RoundTrip_FreshThenStale(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	c := New(Config{
		Addr:               mr.Addr(),
		CtxTTL:             50 * time.Millisecond,
		StaleIfErrorMaxAge: time.Hour,
	})
	defer func() { _ = c.Close() }()
	ctx := context.Background()

	_, result, err := c.GetMembershipContext(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheMiss, result)

	want := domain.MembershipContext{Roles: []string{"tenant_admin"}}
	require.NoError(t, c.SetMembershipContext(ctx, "t1", "u1", want, mustGen(t, c)))

	got, result, err := c.GetMembershipContext(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheFresh, result)
	assert.Equal(t, want.Roles, got.Roles)

	// Freshness is computed from real wall-clock time (time.Since), which is
	// independent of miniredis's own simulated clock — a real sleep is
	// required here; FastForward only advances miniredis's physical-TTL
	// expiry, not our soft-TTL bookkeeping.
	time.Sleep(70 * time.Millisecond)
	got, result, err = c.GetMembershipContext(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheStale, result)
	assert.Equal(t, want.Roles, got.Roles)

	require.NoError(t, c.EvictMembershipContext(ctx, "t1", "u1"))
	_, result, err = c.GetMembershipContext(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheMiss, result)
}

func TestGetMembershipContext_UnmarshalError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	require.NoError(t, mr.Set(ctxKey("t1", "u1"), "not-json"))

	_, result, err := c.GetMembershipContext(context.Background(), "t1", "u1")
	require.NoError(t, err, "an undecodable entry is a miss, not a Valkey failure (AE-51)")
	assert.Equal(t, domain.CacheMiss, result)
	assert.False(t, mr.Exists(ctxKey("t1", "u1")), "and is deleted")
}

func TestLoadScripts(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	require.NoError(t, c.LoadScripts(context.Background()))

	mr.Close()
	assert.Error(t, c.LoadScripts(context.Background()))
}

func TestGetMembershipContext_ConnectionError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	_, result, err := c.GetMembershipContext(context.Background(), "t1", "u1")
	assert.Error(t, err)
	assert.Equal(t, domain.CacheMiss, result)
}

func TestTenantContext_RoundTrip(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 6*time.Second) // exercise the jitter>0 branch too
	ctx := context.Background()

	_, result, err := c.GetTenantContext(ctx, "t1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheMiss, result)

	want := domain.TenantContext{Plan: "pro", FeatureFlags: []string{"a"}}
	require.NoError(t, c.SetTenantContext(ctx, "t1", want, mustTenantGen(t, c)))

	got, result, err := c.GetTenantContext(ctx, "t1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheFresh, result)
	assert.Equal(t, want.Plan, got.Plan)

	require.NoError(t, c.EvictTenantContext(ctx, "t1"))
	_, result, err = c.GetTenantContext(ctx, "t1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheMiss, result)
}

func TestTenderACL_RoundTrip(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 0)
	ctx := context.Background()

	_, hit, err := c.GetTenderACL(ctx, "t1", "tender-1", "u1")
	require.NoError(t, err)
	assert.False(t, hit)

	want := domain.TenderACL{HasAccess: true, AccessLevel: strPtr(domain.AccessLevelApprove)}
	require.NoError(t, c.SetTenderACL(ctx, "t1", "tender-1", "u1", want, mustGen(t, c)))

	got, hit, err := c.GetTenderACL(ctx, "t1", "tender-1", "u1")
	require.NoError(t, err)
	assert.True(t, hit)
	assert.Equal(t, want, got)
}

func TestGetTenderACL_UnmarshalError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	require.NoError(t, mr.Set(tenderACLKey("t1", "tender-1", "u1"), "not-json"))

	_, hit, err := c.GetTenderACL(context.Background(), "t1", "tender-1", "u1")
	assert.Error(t, err)
	assert.False(t, hit)
}

func TestGetTenderACL_ConnectionError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	_, hit, err := c.GetTenderACL(context.Background(), "t1", "tender-1", "u1")
	assert.Error(t, err)
	assert.False(t, hit)
}

func TestSetTenderACL_MarshalIsAlwaysValid_ConnectionErrorSurfaces(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	err := c.SetTenderACL(context.Background(), "t1", "tender-1", "u1", domain.TenderACL{}, "tok")
	assert.Error(t, err)
}

// TestSetTenderACL_MarshalError exercises the json.Marshal error return
// directly — time.Time.MarshalJSON genuinely errors for a year outside
// [0,9999], the one realistic way TenderACL fails to marshal.
func TestSetTenderACL_MarshalError(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 0)

	err := c.SetTenderACL(context.Background(), "t1", "tender-1", "u1", domain.TenderACL{
		ExpiresAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	}, "tok")
	assert.Error(t, err)
}

func TestEvictTenderACLForUser_ScansAllMatchingKeysAcrossPages(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 0)
	ctx := context.Background()

	// More than one SCAN page's worth (miniredis default COUNT batching)
	// to exercise the cursor-loop, not just a single-page scan.
	gen := mustGen(t, c)
	otherGen, err := c.GetSubjectGen(ctx, "t1", "other-user")
	require.NoError(t, err)
	for i := 0; i < 250; i++ {
		tender := "tender-" + string(rune('a'+i%26)) + string(rune('0'+i%10))
		require.NoError(t, c.SetTenderACL(ctx, "t1", tender+"-x", "u1", domain.TenderACL{HasAccess: true}, gen))
	}
	require.NoError(t, c.SetTenderACL(ctx, "t1", "tender-keep", "other-user", domain.TenderACL{HasAccess: true}, otherGen))

	require.NoError(t, c.EvictTenderACLForUser(ctx, "t1", "u1"))

	_, hit, err := c.GetTenderACL(ctx, "t1", "tender-keep", "other-user")
	require.NoError(t, err)
	assert.True(t, hit)
}

func TestEvictTenderACLForUser_ConnectionError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	err := c.EvictTenderACLForUser(context.Background(), "t1", "u1")
	assert.Error(t, err)
}

// TestEvictTenderACLForUser_DelFails reaches the branch where SCAN succeeds
// (there's a matching key) but the subsequent DEL fails — distinct from
// ConnectionError above, which fails at the first command (SCAN) and never
// reaches DEL at all.
func TestEvictTenderACLForUser_DelFails(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	client.AddHook(failDelHook{})
	t.Cleanup(func() { _ = client.Close() })

	c := &Cache{client: client, tenderACLTTL: time.Hour}
	require.NoError(t, mr.Set(tenderACLKey("t1", "tender-1", "u1"), `{"has_access":true}`))

	err := c.EvictTenderACLForUser(context.Background(), "t1", "u1")
	assert.Error(t, err)
}

func TestNegativeCache_RoundTrip(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 0)
	ctx := context.Background()

	hit, err := c.GetNegative(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Empty(t, hit)

	require.NoError(t, c.SetNegative(ctx, "t1", "u1", domain.DenyUnresolvableSubject, mustGen(t, c)))
	hit, err = c.GetNegative(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, domain.DenyUnresolvableSubject, hit)

	require.NoError(t, c.SetNegative(ctx, "t1", "u1", domain.DenyMemberSuspended, mustGen(t, c)))
	hit, err = c.GetNegative(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, domain.DenyMemberSuspended, hit, "the suspended reason must survive the round trip (AE-51)")

	require.NoError(t, c.EvictNegative(ctx, "t1", "u1"))
	hit, err = c.GetNegative(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Empty(t, hit)
}

// mustTenantGen reads (creating if needed) the t1 tenant write-guard token.
func mustTenantGen(t *testing.T, c *Cache) string {
	t.Helper()
	gen, err := c.GetTenantGen(context.Background(), "t1")
	require.NoError(t, err)
	return gen
}

// mustGen reads (creating if needed) the t1/u1 write-guard token.
func mustGen(t *testing.T, c *Cache) string {
	t.Helper()
	gen, err := c.GetSubjectGen(context.Background(), "t1", "u1")
	require.NoError(t, err)
	return gen
}

// §16 AE-51: every eviction replaces the (tenant,user) token, so a rebuild
// that read the token before an eviction can write neither ae:neg nor
// ae:ctx back. Tokens are never empty and never repeat.
func TestGuardedWrites_SkippedAfterEviction(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	ctx := context.Background()
	m := domain.MembershipContext{Roles: []string{"tenant_admin"}}

	gen := mustGen(t, c)
	assert.NotEmpty(t, gen, "a token is created when there is none")
	assert.Equal(t, gen, mustGen(t, c), "and then reused")
	assert.Equal(t, subjectGenTTL, mr.TTL("ae:gen:t1:u1"))

	// A grant event (EvictNegative) and a revoke event (EvictMembershipContext)
	// land while "I-8" is answering.
	require.NoError(t, c.EvictNegative(ctx, "t1", "u1"))
	tok1 := mustGen(t, c)
	require.NoError(t, c.EvictMembershipContext(ctx, "t1", "u1"))
	tok2 := mustGen(t, c)
	assert.NotEqual(t, gen, tok1, "tokens never repeat")
	assert.NotEqual(t, tok1, tok2, "tokens never repeat")

	require.NoError(t, c.SetNegative(ctx, "t1", "u1", domain.DenyMemberSuspended, gen))
	require.NoError(t, c.SetMembershipContext(ctx, "t1", "u1", m, gen))
	hit, err := c.GetNegative(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Empty(t, hit, "a pre-eviction ae:neg write must be skipped")
	_, res, err := c.GetMembershipContext(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheMiss, res, "a pre-eviction ae:ctx write must be skipped")

	// Writes with the current token go through, with their normal TTLs.
	require.NoError(t, c.SetNegative(ctx, "t1", "u1", domain.DenyMemberSuspended, tok2))
	require.NoError(t, c.SetMembershipContext(ctx, "t1", "u1", m, tok2))
	hit, err = c.GetNegative(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, domain.DenyMemberSuspended, hit)
	got, res, err := c.GetMembershipContext(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, domain.CacheFresh, res)
	assert.Equal(t, m.Roles, got.Roles)
	assert.Equal(t, time.Hour, mr.TTL("ae:neg:t1:u1"), "ae:neg keeps its configured TTL")
	assert.Positive(t, mr.TTL("ae:ctx:t1:u1"))
}

// A token lost after the rebuild read it (maxmemory eviction, a failover)
// must make the write skip, never let it through; an empty token never
// writes at all.
func TestGuardedWrites_LostOrEmptyToken_Skips(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	ctx := context.Background()

	gen := mustGen(t, c)
	mr.Del("ae:gen:t1:u1") // lost
	require.NoError(t, c.SetMembershipContext(ctx, "t1", "u1", domain.MembershipContext{Roles: []string{"x"}}, gen))
	require.NoError(t, c.SetNegative(ctx, "t1", "u1", domain.DenyUnresolvableSubject, ""))
	assert.False(t, mr.Exists("ae:ctx:t1:u1"))
	assert.False(t, mr.Exists("ae:neg:t1:u1"))
}

// The tenant and tender-ACL writes use the same guard: an eviction that
// lands between the token read and the write wins (§16 AE-51).
func TestGuardedWrites_TenantAndTenderACL_SkippedAfterEviction(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	ctx := context.Background()

	tgen := mustTenantGen(t, c)
	assert.Equal(t, tgen, mustTenantGen(t, c), "an existing token is reused")
	require.NoError(t, c.EvictTenantContext(ctx, "t1"))
	require.NoError(t, c.SetTenantContext(ctx, "t1", domain.TenantContext{Plan: "pro"}, tgen))
	assert.False(t, mr.Exists("ae:tenant:t1"), "a pre-eviction ae:tenant write must be skipped")
	require.NoError(t, c.SetTenantContext(ctx, "t1", domain.TenantContext{Plan: "pro"}, mustTenantGen(t, c)))
	assert.True(t, mr.Exists("ae:tenant:t1"))

	acl := domain.TenderACL{HasAccess: true}
	gen := mustGen(t, c)
	require.NoError(t, c.EvictTenderACL(ctx, "t1", "tender-1", "u1"))
	require.NoError(t, c.SetTenderACL(ctx, "t1", "tender-1", "u1", acl, gen))
	assert.False(t, mr.Exists("ae:tender_acl:t1:tender-1:u1"), "skipped after EvictTenderACL")

	gen = mustGen(t, c)
	require.NoError(t, c.EvictTenderACLForUser(ctx, "t1", "u1"))
	require.NoError(t, c.SetTenderACL(ctx, "t1", "tender-1", "u1", acl, gen))
	assert.False(t, mr.Exists("ae:tender_acl:t1:tender-1:u1"), "skipped after EvictTenderACLForUser")

	require.NoError(t, c.SetTenderACL(ctx, "t1", "tender-1", "u1", acl, mustGen(t, c)))
	assert.True(t, mr.Exists("ae:tender_acl:t1:tender-1:u1"))
}

func TestEvictTenderACLForUser_TokenWriteError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	assert.Error(t, c.EvictTenderACLForUser(context.Background(), "t1", "u1"))
}

func TestGetTenantGen_ConnectionError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	_, err := c.GetTenantGen(context.Background(), "t1")
	assert.Error(t, err)
}

func TestGetSubjectGen_ConnectionError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	_, err := c.GetSubjectGen(context.Background(), "t1", "u1")
	assert.Error(t, err)
}

// Only the two subject-resolution reasons survive ae:neg. Any other value
// reads as DENY_UNRESOLVABLE_SUBJECT, so a bad entry can never make a member
// get a 401 or 503 from the negative cache.
func TestNegativeCache_OnlySubjectReasonsRoundTrip(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 0)
	ctx := context.Background()
	for _, reason := range domain.DenyReasons() {
		require.NoError(t, c.SetNegative(ctx, "t1", "u1", reason, mustGen(t, c)))
		got, err := c.GetNegative(ctx, "t1", "u1")
		require.NoError(t, err)
		want := domain.DenyUnresolvableSubject
		if reason == domain.DenyMemberSuspended {
			want = domain.DenyMemberSuspended
		}
		assert.Equal(t, want, got, string(reason))
	}
}

// An ae:neg written before AE-51 holds "1". It must still read as a
// non-member, so a rolling deploy never turns it into an Allow or a 5xx.
func TestGetNegative_LegacySentinel_IsUnresolvableSubject(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	require.NoError(t, mr.Set("ae:neg:t1:u1", "1"))

	hit, err := c.GetNegative(context.Background(), "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, domain.DenyUnresolvableSubject, hit)
}

func TestGetNegative_ConnectionError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	_, err := c.GetNegative(context.Background(), "t1", "u1")
	assert.Error(t, err)
}

func TestSetJittered_MarshalError(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 0)
	// Channels are never JSON-marshalable — exercises setJittered's marshal
	// error branch, which no real caller can reach through the exported API
	// (every concrete type this service actually caches marshals cleanly).
	err := c.setJittered(context.Background(), "bad-key", make(chan int), time.Second, 0, time.Second, genGuard{})
	assert.Error(t, err)
}

func TestMarkProcessed_ConnectionError(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	_, err := c.MarkProcessed(context.Background(), "iam-authz-enrichment", "evt-1")
	assert.Error(t, err)
}

func TestMarkProcessed_IdempotentThenEvictAllowsRetry(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 0)
	ctx := context.Background()

	first, err := c.MarkProcessed(ctx, "iam-authz-enrichment", "evt-1")
	require.NoError(t, err)
	assert.True(t, first)

	second, err := c.MarkProcessed(ctx, "iam-authz-enrichment", "evt-1")
	require.NoError(t, err)
	assert.False(t, second)

	require.NoError(t, c.EvictProcessed(ctx, "iam-authz-enrichment", "evt-1"))
	third, err := c.MarkProcessed(ctx, "iam-authz-enrichment", "evt-1")
	require.NoError(t, err)
	assert.True(t, third, "after EvictProcessed a retry must be allowed")
}

func TestRealmAndRestrictedFacts_RoundTripAndConnectionErrors(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	ctx := context.Background()

	tenant, ok, err := c.GetRealm(ctx, "realm-1")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Empty(t, tenant)

	require.NoError(t, c.SetRealm(ctx, "realm-1", "tenant-1"))
	tenant, ok, err = c.GetRealm(ctx, "realm-1")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "tenant-1", tenant)

	restricted, err := c.GetRestricted(ctx, "tenant-1", "tender-9")
	require.NoError(t, err)
	assert.False(t, restricted)
	require.NoError(t, c.SetRestricted(ctx, "tenant-1", "tender-9"))
	restricted, err = c.GetRestricted(ctx, "tenant-1", "tender-9")
	require.NoError(t, err)
	assert.True(t, restricted)

	mr.Close()
	_, _, err = c.GetRealm(ctx, "realm-1")
	assert.Error(t, err)
	assert.Error(t, c.SetRealm(ctx, "realm-1", "tenant-1"))
	_, err = c.GetRestricted(ctx, "tenant-1", "tender-9")
	assert.Error(t, err)
	assert.Error(t, c.SetRestricted(ctx, "tenant-1", "tender-9"))
}

func TestHealth_ReportsConnectionFailure(t *testing.T) {
	t.Parallel()
	c, mr := newTestCache(t, 0)
	mr.Close()

	assert.Error(t, c.Health(context.Background()))
}

func TestClose_IsIdempotentSafe(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, 0)
	assert.NoError(t, c.Close())
}

// Sanity check that redis.Nil itself (not wrapped) is what miniredis
// returns on a genuine miss, confirming Miss vs connection-error
// classification throughout this file rests on the right signal.
func TestRedisNilIsTheMissSignal(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()

	err := client.Get(context.Background(), "nope").Err()
	assert.ErrorIs(t, err, redis.Nil)
}

func strPtr(s string) *string { return &s }

// WithTimeouts shares the Valkey and TTL settings but has its own pool and
// socket timeouts, and leaves the original Cache untouched.
func TestCache_WithTimeouts(t *testing.T) {
	c, mr := newTestCache(t, 0)
	ev := c.WithTimeouts(time.Second, 500*time.Millisecond, 400*time.Millisecond)
	t.Cleanup(func() { _ = ev.Close() })

	assert.NotSame(t, c.client, ev.client, "a separate connection pool")
	assert.Equal(t, time.Second, ev.client.Options().DialTimeout)
	assert.Equal(t, 500*time.Millisecond, ev.client.Options().ReadTimeout)
	assert.Equal(t, 400*time.Millisecond, ev.client.Options().WriteTimeout)
	assert.NotEqual(t, 500*time.Millisecond, c.client.Options().ReadTimeout, "the original keeps its timeouts")
	assert.Equal(t, c.ctxTTL, ev.ctxTTL)
	assert.Equal(t, c.processedTTL, ev.processedTTL)

	require.NoError(t, ev.SetRestricted(context.Background(), "t1", "td1"))
	assert.True(t, mr.Exists(restrictedFactKey("t1", "td1")), "writes reach the same Valkey")
	got, err := c.GetRestricted(context.Background(), "t1", "td1")
	require.NoError(t, err)
	assert.True(t, got, "and are visible through the original")
}

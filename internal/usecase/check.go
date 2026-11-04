package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/v2/pkg/gincommon"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain/policy"
)

// tracer provides the §10 child spans (authz.lookup_cache/evaluate_policy/
// i8_call/i12_call/mfa_freshness_call). The outer ext_authz span comes from
// platform-gincommon's gRPC tracing interceptor via context propagation —
// this package only ever adds children to whatever span is already on ctx.
var tracer = gincommon.NewTracer("github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase")

// CheckInput is everything the inbound gRPC adapter has decoded from a
// CheckRequest before handing off to Checker.Check. Claims come from
// Envoy-jwt_authn-validated attributes only (§8.1); Request comes from the
// route's ContextExtensions plus the raw HTTP method/path.
type CheckInput struct {
	Claims  Claims
	Request policy.RequestFacts
}

// CheckerConfig configures a Checker's tunables. TTLs and the Valkey
// timeouts live in the outbound adapters (valkey.Config); the Org &
// Membership deadlines live here because which one applies is a usecase
// decision (§9.2).
type CheckerConfig struct {
	SharedRealmIssuer string
	// I8Timeout bounds I-8 when a stale entry can answer a failure, and
	// every I-14 call (ORG_MEMBERSHIP_TIMEOUT).
	I8Timeout time.Duration
	// I8ColdTimeout bounds I-8 when nothing can (ORG_MEMBERSHIP_COLD_TIMEOUT):
	// a timeout there is a certain deny, so a slow answer is better.
	// Zero leaves the call bounded by the caller's context and the client.
	I8ColdTimeout time.Duration
	// OperatorIssuer is the platform realm's issuer (CD-52, §8.9). Tokens
	// from it take the operator path instead of tenant resolution. Empty
	// disables the operator path.
	OperatorIssuer string
}

// Checker orchestrates the full §3.1 precedence chain. It depends only on
// the Cache/OrgMembershipClient/Logger/Recorder ports — never on a concrete
// adapter.
type Checker struct {
	cache      Cache
	org        OrgMembershipClient
	realmMap   *RealmMap
	restricted *RestrictedTenderSet
	log        Logger
	metrics    Recorder
	cfg        CheckerConfig
	sf         singleflight.Group
	now        func() time.Time
}

// NewChecker builds a Checker. now defaults to time.Now — tests override it
// to exercise MFA-freshness/stale-if-error boundaries deterministically.
func NewChecker(cache Cache, org OrgMembershipClient, realmMap *RealmMap, restricted *RestrictedTenderSet, log Logger, metrics Recorder, cfg CheckerConfig) *Checker {
	return &Checker{
		cache:      cache,
		org:        org,
		realmMap:   realmMap,
		restricted: restricted,
		log:        log,
		metrics:    metrics,
		cfg:        cfg,
		now:        time.Now,
	}
}

// SetClock overrides the clock used for MFA-freshness comparisons. Test-only.
func (c *Checker) SetClock(now func() time.Time) { c.now = now }

// Check evaluates the §3.1 precedence chain and returns exactly one
// Decision. The first failing check wins — evaluation order below matches
// the doc's numbered list exactly; do not reorder these steps.
func (c *Checker) Check(ctx context.Context, in CheckInput) domain.Decision {
	start := c.now()
	decision := c.check(ctx, in)
	c.metrics.ObserveDecisionLatency(c.now().Sub(start))
	c.metrics.ObserveDecision(decision.Reason, decision.Allow)
	return decision
}

func (c *Checker) check(ctx context.Context, in CheckInput) domain.Decision {
	// §8.1: the verified subject is the only identity input; no other claim
	// or header substitutes for it. With none there is nothing to authorize.
	if in.Claims.Subject == "" {
		return domain.Denied(domain.DenyMalformedIdentity)
	}
	// CD-52 / §8.9: a platform-realm (operator) token never reaches tenant
	// resolution — it is authorized on the operator path or denied there.
	if c.isOperatorToken(in.Claims) {
		return c.checkOperator(in)
	}
	// §2 point 3 / §9: tenant resolution. Malformed identity short-circuits
	// everything — there is no tenant to scope any subsequent call to.
	tenant, ok := ResolveTenant(ctx, in.Claims, c.realmMap, c.cfg.SharedRealmIssuer)
	if !ok {
		return domain.Denied(domain.DenyMalformedIdentity)
	}
	subject := in.Claims.Subject

	reqFacts := in.Request
	if reqFacts.TenderID != "" {
		reqFacts.TenderRestricted = c.restricted.IsRestricted(ctx, tenant, reqFacts.TenderID)
	}

	// §3.1 step 1: subject resolution. Short-circuits everything else.
	cacheCtx, cacheSpan := tracer.Start(ctx, "authz.lookup_cache")
	membership, tenantCtx, reason, resolved := c.resolveContext(cacheCtx, tenant, subject)
	cacheSpan.End()
	if !resolved {
		return domain.Denied(reason)
	}

	policyCtx, policySpan := tracer.Start(ctx, "authz.evaluate_policy")
	defer policySpan.End()

	// §3.1 step 2: subscription read-only enforcement. Blanket tenant-level
	// gate; read methods are never affected.
	if policy.ViolatesReadOnly(tenantCtx.ReadOnly, reqFacts.IsMutation()) {
		return domain.Denied(domain.DenyTenantReadOnly)
	}

	// §3.1 step 3: base role/department policy — 3 of the 4 HLD-seed
	// policies (the 4th, the tender-ACL overlay, runs separately at step 4).
	if !policy.EvaluateBase(policy.Input{Subject: subject, Membership: membership, Request: reqFacts}) {
		return domain.Denied(domain.DenyRoleInsufficient)
	}

	// §3.1 step 4: tender-ACL overlay. Only evaluated because step 3 passed.
	//
	// Guard: a route that carries required_access_level but yields no
	// extractable TenderID (e.g. a trailing-slash path /tenders/ or a
	// misconfigured Envoy route) cannot be correctly evaluated. Deny
	// rather than silently skip the overlay — the service cannot tell
	// "no tender applies" apart from "path parsing failed" otherwise.
	if reqFacts.RequiredAccessLevel != "" && reqFacts.TenderID == "" {
		return domain.Denied(domain.DenyMalformedIdentity)
	}
	if reqFacts.RequiresTenderACL() {
		acl, err := c.resolveTenderACL(policyCtx, tenant, reqFacts.TenderID, subject)
		if err != nil {
			// §7 row 4: fails closed for this overlay only — never escalates
			// to DENY_SERVICE_UNAVAILABLE or denies non-tender-scoped aspects.
			c.metrics.ObserveTACDependencyError()
			return domain.Denied(domain.DenyTenderACLInsufficient)
		}
		if !acl.Satisfies(reqFacts.RequiredAccessLevel) {
			return domain.Denied(domain.DenyTenderACLInsufficient)
		}
	}

	// §3.1 step 5: MFA freshness gate. Evaluated last, only for
	// approver-gated actions — it's a live, uncached call (§4.4).
	if reqFacts.RequiresApproverGate() {
		if denied := c.checkMFAFreshness(policyCtx, tenant, in.Claims); denied {
			return domain.Denied(domain.DenyMFAStale)
		}
	}

	// CD-37 / §16 AE-40: normalise residency_mode for fresh I-8 results.
	// Cache hits are already normalised by GetTenantContext at the decode layer
	// (domain.TenantContext.NormaliseResidencyMode). This guard covers only
	// the cache-miss path where the raw I-8 value arrives here directly before
	// being stored — the Warn + metric are intentional for that path only.
	if tenantCtx.ResidencyMode != "standard" && tenantCtx.ResidencyMode != "strict" {
		c.log.Warn("unknown residency_mode, defaulting to strict",
			map[string]interface{}{"tenant": tenant, "value": tenantCtx.ResidencyMode})
		c.metrics.ObserveResidencyUnknown()
		tenantCtx.ResidencyMode = "strict"
	}

	return domain.Allowed(buildHeaders(tenant, subject, membership, tenantCtx, in.Claims.AuthTime))
}

func buildHeaders(tenant, subject string, m domain.MembershipContext, t domain.TenantContext, authTime int64) map[string]string {
	departments := make([]string, 0, len(m.Departments))
	for _, d := range m.Departments {
		departments = append(departments, d.DepartmentID+":"+d.Level)
	}
	// x-feature-flags is I-8's feature_flags[] verbatim, with one server-side
	// addition: when the tenant is in read-only (cancelled-grace) mode the
	// "read_only" flag is appended so downstream services can adapt their UI
	// (hide write actions, show an upgrade banner) without a separate API call.
	// Mutations are already denied at §3.1 step 2, so this header is only ever
	// seen on allowed read requests — consistent with the gap-closure contract
	// (IAM-to-Commercial-Gap-Closure-Summary §4.6).
	// Only copy the slice when ReadOnly=true to avoid a per-request heap
	// allocation on the common (active tenant, non-read-only) path.
	var featureFlagsHeader string
	if t.ReadOnly {
		featureFlagsHeader = strings.Join(append(append([]string{}, t.FeatureFlags...), "read_only"), ",")
	} else {
		featureFlagsHeader = strings.Join(t.FeatureFlags, ",")
	}
	headers := map[string]string{
		domain.HeaderTenantID:     tenant,
		domain.HeaderUserID:       subject,
		domain.HeaderDepartments:  strings.Join(departments, ","),
		domain.HeaderTenantRoles:  strings.Join(m.Roles, ","),
		domain.HeaderPlan:         t.Plan,
		domain.HeaderFeatureFlags: featureFlagsHeader,
		// x-residency-mode is always server-computed — never read from the
		// inbound request (§16 AE-40). The check() caller has already
		// normalised ResidencyMode to "standard" or "strict".
		domain.HeaderResidencyMode: t.ResidencyMode,
	}
	// x-auth-time is injected only when auth_time is non-zero (§16 AE-49).
	// Tender Service reads this as RFC 3339 UTC to populate mfa_verified_at in
	// approval evidence entries and TenderDeliverableApproved events (AE-TND-F1).
	if v := formatAuthTime(authTime); v != "" {
		headers[domain.HeaderAuthTime] = v
	}
	return headers
}

// formatAuthTime converts a Unix auth_time claim to the RFC 3339 UTC string
// injected as x-auth-time (§16 AE-49). Returns "" when authTime is zero
// (claim absent or JWT carrying literal epoch zero), which callers use as the
// "do not inject" sentinel. Shared by buildHeaders (tenant path) and
// operatorDecision (operator path) so both always emit the same format.
func formatAuthTime(authTime int64) string {
	if authTime == 0 {
		return ""
	}
	return time.Unix(authTime, 0).UTC().Format(time.RFC3339)
}

// sfResult is the value coalesced across concurrent singleflight callers.
type sfResult struct {
	membership domain.MembershipContext
	tenant     domain.TenantContext
}

// resolveContext implements §3.1 step 1 together with the read-through
// cache (§4) and the §7 failure-handling matrix. resolved=false means the
// caller must return Denied(reason) immediately.
func (c *Checker) resolveContext(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, domain.DenyReason, bool) {
	// Run both Valkey reads concurrently rather than sequentially — at the
	// default 10ms VALKEY_READ_TIMEOUT, two sequential reads can alone
	// approach the documented 15ms p99 decision budget (§11.1) on a slow-
	// but-not-erroring Valkey, even though each individual read is well
	// within budget on its own.
	var (
		ctxVal       domain.MembershipContext
		ctxResult    domain.CacheResult
		ctxErr       error
		tenantVal    domain.TenantContext
		tenantResult domain.CacheResult
		tenantErr    error
	)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ctxVal, ctxResult, ctxErr = c.cache.GetMembershipContext(ctx, tenant, user)
	}()
	go func() {
		defer wg.Done()
		tenantVal, tenantResult, tenantErr = c.cache.GetTenantContext(ctx, tenant)
	}()
	wg.Wait()
	valkeyReachable := ctxErr == nil && tenantErr == nil

	if valkeyReachable && ctxResult == domain.CacheFresh && tenantResult == domain.CacheFresh {
		c.metrics.ObserveCacheHit(true)
		return ctxVal, tenantVal, "", true
	}
	c.metrics.ObserveCacheHit(false)

	if valkeyReachable {
		neg, negErr := c.cache.GetNegative(ctx, tenant, user)
		if negErr == nil {
			c.metrics.ObserveNegativeCacheHit(neg)
			if neg {
				return domain.MembershipContext{}, domain.TenantContext{}, domain.DenyUnresolvableSubject, false
			}
		}
	}

	staleAvailable := valkeyReachable && ctxResult != domain.CacheMiss && tenantResult != domain.CacheMiss

	// With no stale entry a failed I-8 is a certain deny, so the call gets
	// the longer cold deadline. Cold and warm callers coalesce separately:
	// a cold caller must not inherit a warm call's shorter deadline.
	key, i8Timeout := tenant+":"+user, c.cfg.I8Timeout
	if !staleAvailable {
		key, i8Timeout = key+":cold", c.cfg.I8ColdTimeout
	}
	// The shared call must not inherit any one caller's cancellation:
	// singleflight hands every coalesced caller the first caller's result, so
	// if Envoy's deadline cancelled that first request, every other request
	// waiting on the same (tenant, user) would fail too — healthy requests
	// denied as DENY_SERVICE_UNAVAILABLE. WithoutCancel keeps the trace and
	// values; the call stays bounded by i8Timeout. Each caller still
	// honours its own deadline for everything after this point.
	sharedCtx := context.WithoutCancel(ctx)
	v, err, shared := c.sf.Do(key, func() (any, error) {
		i8Ctx, cancel := withTimeout(sharedCtx, i8Timeout)
		defer cancel()
		i8Ctx, i8Span := tracer.Start(i8Ctx, "authz.i8_call")
		defer i8Span.End()
		i8Start := c.now()
		m, t, sfErr := c.org.GetMemberships(i8Ctx, tenant, user)
		c.metrics.ObserveI8Latency(c.now().Sub(i8Start))
		return sfResult{membership: m, tenant: t}, sfErr
	})
	if shared {
		c.metrics.ObserveSingleflightCoalesced()
	}

	if err == nil {
		res := v.(sfResult)
		if valkeyReachable {
			if setErr := c.cache.SetMembershipContext(ctx, tenant, user, res.membership); setErr != nil {
				c.log.Warn("failed to write ae:ctx", map[string]interface{}{"error": setErr.Error()})
			}
			if setErr := c.cache.SetTenantContext(ctx, tenant, res.tenant); setErr != nil {
				c.log.Warn("failed to write ae:tenant", map[string]interface{}{"error": setErr.Error()})
			}
		}
		return res.membership, res.tenant, "", true
	}

	if errors.Is(err, domain.ErrNotFound) {
		if valkeyReachable {
			if setErr := c.cache.SetNegative(ctx, tenant, user); setErr != nil {
				c.log.Warn("failed to write ae:neg", map[string]interface{}{"error": setErr.Error()})
			}
			// An authoritative non-member answer (404, or a non-active
			// status — AE-47) must also drop any earlier ae:ctx envelope:
			// O&M emits no event on suspend, so without this the stale
			// envelope (soft TTL + up to AE_STALE_IF_ERROR_MAX_AGE) keeps
			// the member's old roles and §7 stale-if-error would Allow
			// them on the next I-8 outage.
			if ctxResult != domain.CacheMiss {
				if evictErr := c.cache.EvictMembershipContext(ctx, tenant, user); evictErr != nil {
					c.log.Warn("failed to evict ae:ctx", map[string]interface{}{"error": evictErr.Error()})
				}
			}
		}
		return domain.MembershipContext{}, domain.TenantContext{}, domain.DenyUnresolvableSubject, false
	}

	// Sibling unreachable (§7). ErrNotFound handled above; anything else —
	// including an unexpected/unclassified error — is treated as an
	// availability failure so this defensively fails closed rather than
	// risking an accidental Allow on a bug.
	outcome := DecideDependencyOutcome(DependencyState{
		ValkeyReachable:     valkeyReachable,
		SiblingReachable:    false,
		StaleEntryAvailable: staleAvailable,
	})
	//nolint:exhaustive // default deliberately covers OutcomeFailClosed AND
	// OutcomeNormal: this call site hardcodes SiblingReachable: false above
	// (we're only in this branch because the sibling call just failed), so
	// DecideDependencyOutcome can never actually return OutcomeNormal — but
	// default also means any future DependencyOutcome value fails closed
	// here by default, rather than risking an accidental Allow on a bug.
	switch outcome {
	case OutcomeServeStale:
		c.metrics.ObserveStaleIfErrorServed()
		return ctxVal, tenantVal, "", true
	default:
		c.log.Error("membership rebuild failed, no stale entry available", map[string]interface{}{
			"tenant": tenant, "error": err.Error(),
		})
		return domain.MembershipContext{}, domain.TenantContext{}, domain.DenyServiceUnavailable, false
	}
}

// resolveTenderACL implements §6 point 2 / §4.1's 15s-TTL tender-ACL cache.
// No stale-if-error branch — a cache miss always calls through, and a
// sibling failure here is scoped to the overlay by the caller (§7 row 4).
func (c *Checker) resolveTenderACL(ctx context.Context, tenant, tenderID, user string) (domain.TenderACL, error) {
	if acl, hit, err := c.cache.GetTenderACL(ctx, tenant, tenderID, user); err == nil && hit {
		return acl, nil
	}
	i12Ctx, i12Span := tracer.Start(ctx, "authz.i12_call")
	i12Start := c.now()
	acl, err := c.org.GetTenderACL(i12Ctx, tenant, tenderID, user)
	c.metrics.ObserveI12Latency(c.now().Sub(i12Start))
	i12Span.End()
	if err != nil {
		return domain.TenderACL{}, fmt.Errorf("tender acl rebuild: %w", err)
	}
	if setErr := c.cache.SetTenderACL(ctx, tenant, tenderID, user, acl); setErr != nil {
		c.log.Warn("failed to write ae:tender_acl", map[string]interface{}{"error": setErr.Error()})
	}
	return acl, nil
}

// checkMFAFreshness implements §3.1 step 5 / §4.4. Returns true if the
// request must be denied (stale MFA or an unreachable freshness call — see
// the comment below on why a call failure also denies rather than allowing).
func (c *Checker) checkMFAFreshness(ctx context.Context, tenant string, claims Claims) bool {
	mfaCtx, cancel := withTimeout(ctx, c.cfg.I8Timeout)
	defer cancel()
	mfaCtx, mfaSpan := tracer.Start(mfaCtx, "authz.mfa_freshness_call")
	mfaStart := c.now()
	window, err := c.org.GetMFAFreshness(mfaCtx, tenant)
	c.metrics.ObserveI14Latency(c.now().Sub(mfaStart))
	mfaSpan.End()
	if err != nil {
		// The doc gives tender-ACL its own explicit "fail closed for that
		// overlay only" rule (§7 row 4) but is silent on this call failing.
		// Approver-gated actions are exactly the security-sensitive case
		// this service exists to protect, so on ambiguity this fails closed
		// too, denying with DENY_MFA_STALE — the client's remedy (re-auth)
		// is the same one it would already be told to take for a genuinely
		// stale MFA assertion.
		c.log.Error("mfa-freshness call failed", map[string]interface{}{"tenant": tenant, "error": err.Error()})
		return true
	}
	authTime := time.Unix(claims.AuthTime, 0)
	// A future auth_time is either a replayed/forged token or a clock-skew
	// beyond any reasonable tolerance — neither should pass an approver-gate.
	// Without this guard, now.Sub(future) is a large negative duration, which
	// is never > window (positive), so the check would silently allow instead
	// of deny.
	if authTime.After(c.now()) {
		return true
	}
	return c.now().Sub(authTime) > window
}

// withTimeout is context.WithTimeout, except that d <= 0 adds no deadline.
func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

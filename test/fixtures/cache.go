// Package fixtures holds hand-written fakes implementing this service's
// ports — no gomock/mockery, matching the rest of the IAM fleet's testing
// convention.
package fixtures

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

type ctxEntry struct {
	v      domain.MembershipContext
	result domain.CacheResult
}

type tenantEntry struct {
	v      domain.TenantContext
	result domain.CacheResult
}

// FakeCache implements usecase.Cache (and consumer.IdempotencyStore) as an
// in-memory, call-logging fake. Zero value is a healthy, empty cache — set
// the Err* fields to simulate a Valkey connection-level failure, and preset
// the *Preset maps to simulate an existing (Fresh/Stale) entry.
type FakeCache struct {
	mu sync.Mutex

	ctx        map[string]ctxEntry
	tenant     map[string]tenantEntry
	tender     map[string]domain.TenderACL
	neg        map[string]domain.DenyReason
	gen        map[string]string
	genSeq     int
	proc       map[string]bool
	realm      map[string]string
	restricted map[string]bool

	// Err* simulate a Valkey connection-level failure on the matching
	// operation family. A non-nil error here is what usecase.DependencyState
	// .ValkeyReachable=false models — never set these to simulate a plain
	// cache miss, which is the zero-value default already.
	CtxErr            error
	TenantErr         error
	NegErr            error
	GenErr            error
	TenantGenErr      error
	MarkProcessedErr  error
	EvictProcessedErr error

	// Set*Err/Evict*Err simulate a write-side failure on the matching
	// operation — distinct from the Get-side Err* fields above, so a test
	// can make reads succeed while a specific write fails (or vice versa).
	SetCtxErr                  error
	SetTenantErr               error
	SetTenderACLErr            error
	SetNegErr                  error
	GetTenderACLErr            error
	EvictCtxErr                error
	EvictTenantErr             error
	EvictNegErr                error
	EvictTACLSingleErr         error // gates EvictTenderACL (targeted single-key DEL, AE-TND-G1)
	EvictTACLScanErr           error // gates EvictTenderACLForUser (SCAN-based, MembershipRevoked/UserDeleted)
	RealmErr                   error
	RestrictedErr              error
	SetRealmErr                error
	SetRestrictedErr           error
	EvictRestrictedByTenantErr error
	EvictRealmsByTenantErr     error

	Calls []string
}

// NewFakeCache builds an empty, healthy FakeCache.
func NewFakeCache() *FakeCache {
	return &FakeCache{
		ctx:        map[string]ctxEntry{},
		tenant:     map[string]tenantEntry{},
		tender:     map[string]domain.TenderACL{},
		neg:        map[string]domain.DenyReason{},
		gen:        map[string]string{},
		proc:       map[string]bool{},
		realm:      map[string]string{},
		restricted: map[string]bool{},
	}
}

func ctxKey(tenant, user string) string { return tenant + ":" + user }
func tenderKey(t, tr, u string) string  { return t + ":" + tr + ":" + u }

func (f *FakeCache) record(call string) {
	f.Calls = append(f.Calls, call)
}

// SortedCalls returns Calls sorted — convenient for order-independent
// assertions ("exactly these keys were touched, nothing else").
func (f *FakeCache) SortedCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string{}, f.Calls...)
	sort.Strings(out)
	return out
}

// SeedMembershipContext presets a (tenant,user) entry as Fresh or Stale
// (never call this to simulate Miss — just don't seed anything).
func (f *FakeCache) SeedMembershipContext(tenant, user string, v domain.MembershipContext, result domain.CacheResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ctx[ctxKey(tenant, user)] = ctxEntry{v: v, result: result}
}

// SeedTenantContext presets a tenant's context entry.
func (f *FakeCache) SeedTenantContext(tenant string, v domain.TenantContext, result domain.CacheResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tenant[tenant] = tenantEntry{v: v, result: result}
}

// SeedNegative presets the ae:neg sentinel for (tenant,user) as a non-member
// (DENY_UNRESOLVABLE_SUBJECT).
func (f *FakeCache) SeedNegative(tenant, user string) {
	f.SeedNegativeReason(tenant, user, domain.DenyUnresolvableSubject)
}

// SeedNegativeReason presets the ae:neg sentinel for (tenant,user) holding reason.
func (f *FakeCache) SeedNegativeReason(tenant, user string, reason domain.DenyReason) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.neg[ctxKey(tenant, user)] = reason
}

func (f *FakeCache) GetMembershipContext(_ context.Context, tenant, user string) (domain.MembershipContext, domain.CacheResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetMembershipContext:" + ctxKey(tenant, user))
	if f.CtxErr != nil {
		return domain.MembershipContext{}, domain.CacheMiss, f.CtxErr
	}
	e, ok := f.ctx[ctxKey(tenant, user)]
	if !ok {
		return domain.MembershipContext{}, domain.CacheMiss, nil
	}
	return e.v, e.result, nil
}

// SetMembershipContext writes only while the token still equals gen, like
// the valkey script; a skipped write is recorded as "SetMembershipContextSkipped:".
func (f *FakeCache) SetMembershipContext(_ context.Context, tenant, user string, v domain.MembershipContext, gen string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetMembershipContext:" + ctxKey(tenant, user))
	if f.SetCtxErr != nil {
		return f.SetCtxErr
	}
	if !f.guardOK(tenant, user, gen) {
		f.record("SetMembershipContextSkipped:" + ctxKey(tenant, user))
		return nil
	}
	f.ctx[ctxKey(tenant, user)] = ctxEntry{v: v, result: domain.CacheFresh}
	return nil
}

func (f *FakeCache) EvictMembershipContext(_ context.Context, tenant, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("EvictMembershipContext:" + ctxKey(tenant, user))
	if f.EvictCtxErr != nil {
		return f.EvictCtxErr
	}
	delete(f.ctx, ctxKey(tenant, user))
	f.bumpGen(tenant, user)
	return nil
}

func (f *FakeCache) GetTenantContext(_ context.Context, tenant string) (domain.TenantContext, domain.CacheResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetTenantContext:" + tenant)
	if f.TenantErr != nil {
		return domain.TenantContext{}, domain.CacheMiss, f.TenantErr
	}
	e, ok := f.tenant[tenant]
	if !ok {
		return domain.TenantContext{}, domain.CacheMiss, nil
	}
	tc := e.v
	tc.NormaliseResidencyMode()
	return tc, e.result, nil
}

// GetTenantGen returns the tenant write-guard token, creating one if none.
func (f *FakeCache) GetTenantGen(_ context.Context, tenant string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetTenantGen:" + tenant)
	if f.TenantGenErr != nil {
		return "", f.TenantGenErr
	}
	if f.gen[tenantGenKey(tenant)] == "" {
		f.replaceGen(tenantGenKey(tenant))
	}
	return f.gen[tenantGenKey(tenant)], nil
}

// SetTenantContext writes only while the tenant token still equals gen.
func (f *FakeCache) SetTenantContext(_ context.Context, tenant string, v domain.TenantContext, gen string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetTenantContext:" + tenant)
	if f.SetTenantErr != nil {
		return f.SetTenantErr
	}
	if gen == "" || f.gen[tenantGenKey(tenant)] != gen {
		f.record("SetTenantContextSkipped:" + tenant)
		return nil
	}
	f.tenant[tenant] = tenantEntry{v: v, result: domain.CacheFresh}
	return nil
}

func (f *FakeCache) EvictTenantContext(_ context.Context, tenant string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("EvictTenantContext:" + tenant)
	if f.EvictTenantErr != nil {
		return f.EvictTenantErr
	}
	delete(f.tenant, tenant)
	f.replaceGen(tenantGenKey(tenant))
	return nil
}

func (f *FakeCache) GetTenderACL(_ context.Context, tenant, tender, user string) (domain.TenderACL, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetTenderACL:" + tenderKey(tenant, tender, user))
	if f.GetTenderACLErr != nil {
		return domain.TenderACL{}, false, f.GetTenderACLErr
	}
	v, ok := f.tender[tenderKey(tenant, tender, user)]
	return v, ok, nil
}

// SetTenderACL writes only while the (tenant,user) token still equals gen.
func (f *FakeCache) SetTenderACL(_ context.Context, tenant, tender, user string, v domain.TenderACL, gen string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetTenderACL:" + tenderKey(tenant, tender, user))
	if f.SetTenderACLErr != nil {
		return f.SetTenderACLErr
	}
	if !f.guardOK(tenant, user, gen) {
		f.record("SetTenderACLSkipped:" + tenderKey(tenant, tender, user))
		return nil
	}
	f.tender[tenderKey(tenant, tender, user)] = v
	return nil
}

func (f *FakeCache) EvictTenderACL(_ context.Context, tenant, tender, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("EvictTenderACL:" + tenderKey(tenant, tender, user))
	if f.EvictTACLSingleErr != nil {
		return f.EvictTACLSingleErr
	}
	delete(f.tender, tenderKey(tenant, tender, user))
	f.bumpGen(tenant, user)
	return nil
}

func (f *FakeCache) EvictTenderACLForUser(_ context.Context, tenant, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("EvictTenderACLForUser:" + ctxKey(tenant, user))
	if f.EvictTACLScanErr != nil {
		return f.EvictTACLScanErr
	}
	f.bumpGen(tenant, user)
	for k := range f.tender {
		parts := strings.Split(k, ":")
		if len(parts) == 3 && parts[0] == tenant && parts[2] == user {
			delete(f.tender, k)
		}
	}
	return nil
}

func (f *FakeCache) GetNegative(_ context.Context, tenant, user string) (domain.DenyReason, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetNegative:" + ctxKey(tenant, user))
	if f.NegErr != nil {
		return "", f.NegErr
	}
	v, ok := f.neg[ctxKey(tenant, user)]
	if !ok {
		return "", nil
	}
	// Same normalisation as valkey.Cache, so a present entry is always a hit.
	return domain.NegativeCacheReason(string(v)), nil
}

// GetSubjectGen returns the write-guard token, creating one if there is
// none (never ""), like valkey.Cache.
func (f *FakeCache) GetSubjectGen(_ context.Context, tenant, user string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetSubjectGen:" + ctxKey(tenant, user))
	if f.GenErr != nil {
		return "", f.GenErr
	}
	if f.gen[ctxKey(tenant, user)] == "" {
		f.bumpGen(tenant, user)
	}
	return f.gen[ctxKey(tenant, user)], nil
}

// guardOK mirrors the valkey script: the token must be non-empty and match.
func (f *FakeCache) guardOK(tenant, user, gen string) bool {
	return gen != "" && f.gen[ctxKey(tenant, user)] == gen
}

// bumpGen replaces the (tenant,user) token, like valkey.Cache's evictions.
// Caller holds mu.
func (f *FakeCache) bumpGen(tenant, user string) {
	f.replaceGen(ctxKey(tenant, user))
}

// replaceGen sets a never-repeating token at key. Caller holds mu.
func (f *FakeCache) replaceGen(key string) {
	f.genSeq++
	f.gen[key] = "tok" + strconv.Itoa(f.genSeq)
}

// tenantGenKey keys the tenant token apart from every ctxKey(tenant,user).
func tenantGenKey(tenant string) string { return "tenant-gen|" + tenant }

// SetNegative writes only while the generation still equals gen, like the
// valkey script; a skipped write is recorded as "SetNegativeSkipped:".
func (f *FakeCache) SetNegative(_ context.Context, tenant, user string, reason domain.DenyReason, gen string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetNegative:" + ctxKey(tenant, user))
	if f.SetNegErr != nil {
		return f.SetNegErr
	}
	if !f.guardOK(tenant, user, gen) {
		f.record("SetNegativeSkipped:" + ctxKey(tenant, user))
		return nil
	}
	f.neg[ctxKey(tenant, user)] = reason
	return nil
}

func (f *FakeCache) EvictNegative(_ context.Context, tenant, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("EvictNegative:" + ctxKey(tenant, user))
	if f.EvictNegErr != nil {
		return f.EvictNegErr
	}
	delete(f.neg, ctxKey(tenant, user))
	f.bumpGen(tenant, user)
	return nil
}

func (f *FakeCache) MarkProcessed(_ context.Context, _, eventID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("MarkProcessed:" + eventID)
	if f.MarkProcessedErr != nil {
		return false, f.MarkProcessedErr
	}
	if f.proc[eventID] {
		return false, nil
	}
	f.proc[eventID] = true
	return true, nil
}

func (f *FakeCache) EvictProcessed(_ context.Context, _, eventID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("EvictProcessed:" + eventID)
	if f.EvictProcessedErr != nil {
		return f.EvictProcessedErr
	}
	delete(f.proc, eventID)
	return nil
}

func (f *FakeCache) EvictRestrictedByTenant(_ context.Context, tenant string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("EvictRestrictedByTenant:" + tenant)
	if f.EvictRestrictedByTenantErr != nil {
		return f.EvictRestrictedByTenantErr
	}
	prefix := tenant + ":"
	for k := range f.restricted {
		if strings.HasPrefix(k, prefix) {
			delete(f.restricted, k)
		}
	}
	return nil
}

func (f *FakeCache) EvictRealmsByTenant(_ context.Context, tenant string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("EvictRealmsByTenant:" + tenant)
	if f.EvictRealmsByTenantErr != nil {
		return f.EvictRealmsByTenantErr
	}
	for realm, t := range f.realm {
		if t == tenant {
			delete(f.realm, realm)
		}
	}
	return nil
}

func (f *FakeCache) GetRealm(_ context.Context, realm string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetRealm:" + realm)
	if f.RealmErr != nil {
		return "", false, f.RealmErr
	}
	tenant, ok := f.realm[realm]
	return tenant, ok, nil
}

func (f *FakeCache) SetRealm(_ context.Context, realm, tenant string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetRealm:" + realm)
	if f.SetRealmErr != nil {
		return f.SetRealmErr
	}
	if f.realm == nil {
		f.realm = map[string]string{}
	}
	f.realm[realm] = tenant
	return nil
}

func (f *FakeCache) GetRestricted(_ context.Context, tenant, tender string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetRestricted:" + tenant + ":" + tender)
	if f.RestrictedErr != nil {
		return false, f.RestrictedErr
	}
	return f.restricted[tenant+":"+tender], nil
}

func (f *FakeCache) SetRestricted(_ context.Context, tenant, tender string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetRestricted:" + tenant + ":" + tender)
	if f.SetRestrictedErr != nil {
		return f.SetRestrictedErr
	}
	if f.restricted == nil {
		f.restricted = map[string]bool{}
	}
	f.restricted[tenant+":"+tender] = true
	return nil
}

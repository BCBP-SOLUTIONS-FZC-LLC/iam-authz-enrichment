// Package fixtures holds hand-written fakes implementing this service's
// ports — no gomock/mockery, matching the rest of the IAM fleet's testing
// convention.
package fixtures

import (
	"context"
	"sort"
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

// FakeCache implements usecase.Cache (and consumer.IdempotencyCache) as an
// in-memory, call-logging fake. Zero value is a healthy, empty cache — set
// the Err* fields to simulate a Valkey connection-level failure, and preset
// the *Preset maps to simulate an existing (Fresh/Stale) entry.
type FakeCache struct {
	mu sync.Mutex

	ctx    map[string]ctxEntry
	tenant map[string]tenantEntry
	tender map[string]domain.TenderACL
	neg    map[string]bool
	proc   map[string]bool

	// Err* simulate a Valkey connection-level failure on the matching
	// operation family. A non-nil error here is what usecase.DependencyState
	// .ValkeyReachable=false models — never set these to simulate a plain
	// cache miss, which is the zero-value default already.
	CtxErr            error
	TenantErr         error
	NegErr            error
	MarkProcessedErr  error
	EvictProcessedErr error

	// Set*Err/Evict*Err simulate a write-side failure on the matching
	// operation — distinct from the Get-side Err* fields above, so a test
	// can make reads succeed while a specific write fails (or vice versa).
	SetCtxErr         error
	SetTenantErr      error
	SetTenderACLErr   error
	SetNegErr         error
	GetTenderACLErr   error
	EvictCtxErr       error
	EvictNegErr       error
	EvictTenderACLErr error

	Calls []string
}

// NewFakeCache builds an empty, healthy FakeCache.
func NewFakeCache() *FakeCache {
	return &FakeCache{
		ctx:    map[string]ctxEntry{},
		tenant: map[string]tenantEntry{},
		tender: map[string]domain.TenderACL{},
		neg:    map[string]bool{},
		proc:   map[string]bool{},
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

// SeedNegative presets the ae:neg sentinel for (tenant,user).
func (f *FakeCache) SeedNegative(tenant, user string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.neg[ctxKey(tenant, user)] = true
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

func (f *FakeCache) SetMembershipContext(_ context.Context, tenant, user string, v domain.MembershipContext) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetMembershipContext:" + ctxKey(tenant, user))
	if f.SetCtxErr != nil {
		return f.SetCtxErr
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
	return e.v, e.result, nil
}

func (f *FakeCache) SetTenantContext(_ context.Context, tenant string, v domain.TenantContext) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetTenantContext:" + tenant)
	if f.SetTenantErr != nil {
		return f.SetTenantErr
	}
	f.tenant[tenant] = tenantEntry{v: v, result: domain.CacheFresh}
	return nil
}

func (f *FakeCache) EvictTenantContext(_ context.Context, tenant string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("EvictTenantContext:" + tenant)
	delete(f.tenant, tenant)
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

func (f *FakeCache) SetTenderACL(_ context.Context, tenant, tender, user string, v domain.TenderACL) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetTenderACL:" + tenderKey(tenant, tender, user))
	if f.SetTenderACLErr != nil {
		return f.SetTenderACLErr
	}
	f.tender[tenderKey(tenant, tender, user)] = v
	return nil
}

func (f *FakeCache) EvictTenderACLForUser(_ context.Context, tenant, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("EvictTenderACLForUser:" + ctxKey(tenant, user))
	if f.EvictTenderACLErr != nil {
		return f.EvictTenderACLErr
	}
	for k := range f.tender {
		parts := strings.Split(k, ":")
		if len(parts) == 3 && parts[0] == tenant && parts[2] == user {
			delete(f.tender, k)
		}
	}
	return nil
}

func (f *FakeCache) GetNegative(_ context.Context, tenant, user string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetNegative:" + ctxKey(tenant, user))
	if f.NegErr != nil {
		return false, f.NegErr
	}
	return f.neg[ctxKey(tenant, user)], nil
}

func (f *FakeCache) SetNegative(_ context.Context, tenant, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetNegative:" + ctxKey(tenant, user))
	if f.SetNegErr != nil {
		return f.SetNegErr
	}
	f.neg[ctxKey(tenant, user)] = true
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
	return nil
}

func (f *FakeCache) MarkProcessed(_ context.Context, eventID string) (bool, error) {
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

func (f *FakeCache) EvictProcessed(_ context.Context, eventID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("EvictProcessed:" + eventID)
	if f.EvictProcessedErr != nil {
		return f.EvictProcessedErr
	}
	delete(f.proc, eventID)
	return nil
}

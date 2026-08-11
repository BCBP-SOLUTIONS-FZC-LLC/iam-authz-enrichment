package fixtures

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// FakeOrgMembershipClient implements usecase.OrgMembershipClient with
// per-test-configurable function fields — the shape of each of the three
// sibling calls varies enough per test scenario that a function-field fake
// is clearer here than a stateful one.
type FakeOrgMembershipClient struct {
	GetMembershipsFunc  func(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, error)
	GetTenderACLFunc    func(ctx context.Context, tenant, tenderID, user string) (domain.TenderACL, error)
	GetMFAFreshnessFunc func(ctx context.Context, tenant string) (time.Duration, error)

	MembershipCalls int64
	TenderACLCalls  int64
	MFACalls        int64
}

func (f *FakeOrgMembershipClient) GetMemberships(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, error) {
	atomic.AddInt64(&f.MembershipCalls, 1)
	if f.GetMembershipsFunc == nil {
		return domain.NewMembershipContext(), domain.NewTenantContext(), nil
	}
	return f.GetMembershipsFunc(ctx, tenant, user)
}

func (f *FakeOrgMembershipClient) GetTenderACL(ctx context.Context, tenant, tenderID, user string) (domain.TenderACL, error) {
	atomic.AddInt64(&f.TenderACLCalls, 1)
	if f.GetTenderACLFunc == nil {
		return domain.TenderACL{}, nil
	}
	return f.GetTenderACLFunc(ctx, tenant, tenderID, user)
}

func (f *FakeOrgMembershipClient) GetMFAFreshness(ctx context.Context, tenant string) (time.Duration, error) {
	atomic.AddInt64(&f.MFACalls, 1)
	if f.GetMFAFreshnessFunc == nil {
		return 0, nil
	}
	return f.GetMFAFreshnessFunc(ctx, tenant)
}

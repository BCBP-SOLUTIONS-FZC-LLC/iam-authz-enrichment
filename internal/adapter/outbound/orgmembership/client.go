// Package orgmembership is the outbound HTTP adapter for the three sibling
// Org & Membership calls (LLD §6): membership rebuild (I-8), tender-ACL
// check (I-12), and the dedicated MFA-freshness read (I-14). All three run
// over mTLS within the mesh with an aggressive, single-digit-ms-beyond-Valkey
// timeout — there's no latency headroom in the 15ms p99 budget to wait on a
// slow sibling call.
package orgmembership

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// ErrNotFound and ErrUnavailable are domain.ErrNotFound/domain.ErrUnavailable
// (aliased here for readability at call sites in this file). I-8's 404 is an
// authoritative answer from a reachable sibling — callers negative-cache it
// and deny DENY_UNRESOLVABLE_SUBJECT, never eligible for §7's
// stale-if-error extension. Everything else unexpected wraps ErrUnavailable,
// the availability failure the §7 matrix reasons about.
var (
	ErrNotFound    = domain.ErrNotFound
	ErrUnavailable = domain.ErrUnavailable
)

// Client calls the three Org & Membership internal endpoints.
type Client struct {
	baseURL string
	http    *http.Client
}

// New builds a Client. timeout is applied to every call — per §6, an
// aggressive timeout that leaves headroom inside the 15ms p99 budget even on
// a cache miss.
func New(baseURL string, timeout time.Duration) *Client {
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: timeout},
	}
}

// departmentDTO/delegationDTO/membershipsResponse mirror I-8's wire shape.
type departmentDTO struct {
	DepartmentID string `json:"department_id"`
	Level        string `json:"level"`
}

type delegationDTO struct {
	FromUserID   string `json:"from_user_id"`
	DepartmentID string `json:"department_id"`
	Level        string `json:"level"`
}

// membershipsResponse is I-8's full response. MFAFreshnessSeconds is present
// on the wire but explicitly informational only — see §4.4. It must never
// flow into any cached struct or into the MFA-freshness gate; the only field
// this type exposes it through is this DTO, and ToDomain() below drops it on
// the floor by construction (there's no field to carry it into
// domain.MembershipContext).
type membershipsResponse struct {
	Roles               []string        `json:"roles"`
	Departments         []departmentDTO `json:"departments"`
	ActiveDelegations   []delegationDTO `json:"active_delegations"`
	Plan                string          `json:"plan"`
	FeatureFlags        []string        `json:"feature_flags"`
	SubscriptionStatus  string          `json:"subscription_status"`
	ReadOnly            bool            `json:"read_only"`
	MFAFreshnessSeconds int             `json:"mfa_freshness_seconds"`
}

// MembershipContext converts the wire response to the domain type actually
// cached under ae:ctx — always empty (never nil) list fields, per the §12
// "empty array, never null" contract-test requirement.
func (r membershipsResponse) MembershipContext() domain.MembershipContext {
	m := domain.NewMembershipContext()
	if r.Roles != nil {
		m.Roles = r.Roles
	}
	for _, d := range r.Departments {
		m.Departments = append(m.Departments, domain.Department{DepartmentID: d.DepartmentID, Level: d.Level})
	}
	for _, d := range r.ActiveDelegations {
		m.Delegations = append(m.Delegations, domain.Delegation{FromUserID: d.FromUserID, DepartmentID: d.DepartmentID, Level: d.Level})
	}
	return m
}

// TenantContext converts the wire response's tenant-scoped slice to the
// domain type cached under ae:tenant (§4.1's explicit split).
func (r membershipsResponse) TenantContext() domain.TenantContext {
	t := domain.NewTenantContext()
	t.Plan = r.Plan
	t.SubscriptionStatus = r.SubscriptionStatus
	t.ReadOnly = r.ReadOnly
	if r.FeatureFlags != nil {
		t.FeatureFlags = r.FeatureFlags
	}
	return t
}

// GetMemberships calls I-8: GET /api/v1/internal/users/:id/memberships.
// Returns ErrNotFound on a 404 (no active membership — §3.1 step 1), or
// ErrUnavailable wrapping the underlying cause on any other failure.
//
// tenant is sent as a query parameter — the documented path
// (/users/:id/memberships) carries no tenant segment, but every outbound
// call must be tenant-scoped by construction (§8.4), and the response itself
// must be scoped to one tenant's membership facts.
func (c *Client) GetMemberships(ctx context.Context, tenant, user string) (domain.MembershipContext, domain.TenantContext, error) {
	u := fmt.Sprintf("%s/api/v1/internal/users/%s/memberships?tenant_id=%s",
		c.baseURL, url.PathEscape(user), url.QueryEscape(tenant))

	var resp membershipsResponse
	if err := c.getJSON(ctx, u, &resp); err != nil {
		return domain.MembershipContext{}, domain.TenantContext{}, err
	}
	return resp.MembershipContext(), resp.TenantContext(), nil
}

// GetTenderACL calls I-12: GET /api/v1/internal/tenants/:id/tenders/:tender_id/acl/:user_id.
// domain.TenderACL's json tags already match I-12's wire shape exactly, so no
// separate DTO is needed for decoding. This endpoint never returns 404 — absence of a grant is HasAccess: false,
// itself a valid, cacheable answer (§6 point 2). Only network/5xx failures
// produce ErrUnavailable here.
func (c *Client) GetTenderACL(ctx context.Context, tenant, tenderID, user string) (domain.TenderACL, error) {
	u := fmt.Sprintf("%s/api/v1/internal/tenants/%s/tenders/%s/acl/%s",
		c.baseURL, url.PathEscape(tenant), url.PathEscape(tenderID), url.PathEscape(user))

	var resp domain.TenderACL
	if err := c.getJSON(ctx, u, &resp); err != nil {
		return domain.TenderACL{}, err
	}
	return resp, nil
}

type mfaFreshnessResponse struct {
	MFAFreshnessSeconds int `json:"mfa_freshness_seconds"`
}

// GetMFAFreshness calls I-14: GET /api/v1/internal/tenants/:id/mfa-freshness.
// This is the ONLY source of mfa_freshness_seconds this service ever acts
// on — see §4.4. The result must never be written to any cache key this
// service owns.
func (c *Client) GetMFAFreshness(ctx context.Context, tenant string) (time.Duration, error) {
	u := fmt.Sprintf("%s/api/v1/internal/tenants/%s/mfa-freshness", c.baseURL, url.PathEscape(tenant))

	var resp mfaFreshnessResponse
	if err := c.getJSON(ctx, u, &resp); err != nil {
		return 0, err
	}
	return time.Duration(resp.MFAFreshnessSeconds) * time.Second, nil
}

func (c *Client) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrUnavailable, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return fmt.Errorf("%w: unexpected status %d", ErrUnavailable, resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%w: decode response: %v", ErrUnavailable, err)
	}
	return nil
}

// Package orgmembership is the outbound HTTP adapter for this service's
// synchronous sibling calls (LLD §6): membership rebuild (I-8) and the
// dedicated MFA-freshness read (I-14) against Org & Membership, plus the
// tender-ACL check (TAC-4, formerly I-12) against iam-tender-acl (ADR-0007
// Wave 3 Phase 4 — that call moved to a different sibling when
// tender_acl_entries was extracted into its own service; the package name
// predates that split and is kept for now to avoid an unrelated rename
// churning this file's history). All three run over mTLS within the mesh
// with an aggressive, single-digit-ms-beyond-Valkey timeout — there's no
// latency headroom in the 15ms p99 budget to wait on a slow sibling call.
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

// Client calls the three sibling internal endpoints: I-8/I-14 against Org &
// Membership, and I-12 against iam-tender-acl (ADR-0007 Wave 3 Phase 4 —
// I-12 moved out of Org & Membership when tender_acl_entries was extracted
// into its own service; I-8/I-14 were unaffected and stay put). Two
// independent base URLs/timeouts/http.Clients, not one shared set, since
// these are now genuinely two different downstream services with two
// different latency budgets.
type Client struct {
	baseURL string
	http    *http.Client

	tenderACLBaseURL string
	tenderACLHTTP    *http.Client
}

// New builds a Client. timeout is applied to every Org & Membership call
// (I-8/I-14) — per §6, an aggressive timeout that leaves headroom inside the
// 15ms p99 budget even on a cache miss. tenderACLTimeout applies only to
// GetTenderACL (I-12), sized against iam-tender-acl's own TAC-4 SLO
// (5ms cache-hit/20ms cache-miss) rather than reused from timeout, since the
// two downstream services no longer share a latency profile.
func New(baseURL string, timeout time.Duration, tenderACLBaseURL string, tenderACLTimeout time.Duration) *Client {
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: timeout},

		tenderACLBaseURL: tenderACLBaseURL,
		tenderACLHTTP:    &http.Client{Timeout: tenderACLTimeout},
	}
}

// departmentDTO/membershipsResponse mirror I-8's wire shape.
type departmentDTO struct {
	DepartmentID string `json:"department_id"`
	Level        string `json:"role_level"`
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

// tenderACLResponse is the TAC-4 wire shape. access_level and expires_at are
// pointer types with omitempty because iam-tender-acl omits both fields when
// has_access is false — a valid, cacheable "no grant" answer. The domain type
// uses plain string/time.Time; this DTO absorbs the wire-vs-domain mismatch.
type tenderACLResponse struct {
	HasAccess   bool       `json:"has_access"`
	AccessLevel *string    `json:"access_level,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// GetTenderACL calls TAC-4 (formerly I-12) on iam-tender-acl: GET
// /internal/tenants/:id/tenders/:tender_id/acl/:user_id — no /api/v1
// prefix, unlike every other internal route in this file. This is
// deliberate, not a typo: iam-tender-acl registers its mesh-only routes
// directly under /internal (tender-acl-service-lld.md §8.3), whereas Org &
// Membership nests internal routes under /api/v1/internal. ADR-0007 Wave 3
// Phase 4 repointed this one call here from Org & Membership's now-retired
// (410 Gone, pending Phase 6 deletion) I-12 handler.
//
// This endpoint never returns 404 — absence of a grant is HasAccess: false,
// itself a valid, cacheable answer (§6 point 2). Only network/5xx failures
// produce ErrUnavailable here.
func (c *Client) GetTenderACL(ctx context.Context, tenant, tenderID, user string) (domain.TenderACL, error) {
	u := fmt.Sprintf("%s/internal/tenants/%s/tenders/%s/acl/%s",
		c.tenderACLBaseURL, url.PathEscape(tenant), url.PathEscape(tenderID), url.PathEscape(user))

	var wire tenderACLResponse
	if err := c.getJSONWith(ctx, c.tenderACLHTTP, u, &wire); err != nil {
		return domain.TenderACL{}, err
	}
	acl := domain.TenderACL{HasAccess: wire.HasAccess}
	if wire.AccessLevel != nil {
		acl.AccessLevel = *wire.AccessLevel
	}
	return acl, nil
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
	return c.getJSONWith(ctx, c.http, u, out)
}

// getJSONWith is getJSON parameterized on which http.Client to use — I-8/
// I-14 (GetMemberships/GetMFAFreshness) go through getJSON's c.http
// (Org & Membership's timeout); GetTenderACL goes through c.tenderACLHTTP
// (iam-tender-acl's own timeout) via this method directly.
func (c *Client) getJSONWith(ctx context.Context, httpClient *http.Client, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrUnavailable, err)
	}
	resp, err := httpClient.Do(req)
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

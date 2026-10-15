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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/gincommon"

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
		http:    instrumentedHTTPClient(timeout),

		tenderACLBaseURL: tenderACLBaseURL,
		tenderACLHTTP:    instrumentedHTTPClient(tenderACLTimeout),
	}
}

// instrumentedHTTPClient matches iam-org-membership's httpx.NewClient:
// otelhttp wraps the transport so every I-8/I-12/I-14 call emits a client
// span and injects W3C traceparent through the TracerProvider
// gincommon.InitTracingWithConfig installed. Without this, outbound calls
// start a parentless trace at the sibling.
func instrumentedHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 40 * time.Millisecond // config.Load's ORG_MEMBERSHIP_TIMEOUT default
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}
}

// departmentDTO/membershipsResponse mirror I-8's wire shape. The level
// field is "role_level" on the wire, not "level" — verified against
// Org & Membership's actual GetMemberships handler, which serializes its
// MembershipProjection.Departments field ([]domain.DeptMembershipView,
// RoleLevel typed with a "role_level" JSON tag) directly, and against that
// service's own LLD, whose documented I-8 response example uses
// "role_level" too. Every other membership-authz-q event/endpoint in that
// service spells the same concept "level" (DepartmentMembershipGranted's
// payload, the PUT department-member endpoints, etc.) — I-8's response is
// the one place it's spelled differently, which is presumably why this
// mismatch went unnoticed for as long as it did: a "level" field
// genuinely exists in that service's vocabulary, just never on this
// specific wire response.
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
	// ResidencyMode is Core's tenants.residency_mode ("standard"|"strict").
	// Added by CD-37. An absent field (pre-CD-37 Core) decodes to "" and the
	// check layer normalises it to "strict" (fail-safe).
	ResidencyMode string `json:"residency_mode,omitempty"`
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
	t.ResidencyMode = r.ResidencyMode
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
	if err := c.getJSON(ctx, tenant, u, &resp); err != nil {
		return domain.MembershipContext{}, domain.TenantContext{}, err
	}
	return resp.MembershipContext(), resp.TenantContext(), nil
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
// domain.TenderACL's json tags already match the wire shape exactly (both
// the old I-12 response and the new TAC-4 response — TAC-4 additionally
// sends expires_at, which I-12 never did, but ExpiresAt is decoded-and-
// unused by this service regardless, so this is a compatible superset, not
// a breaking change). This endpoint never returns 404 — absence of a grant
// is HasAccess: false, itself a valid, cacheable answer (§6 point 2). Only
// network/5xx failures produce ErrUnavailable here.
func (c *Client) GetTenderACL(ctx context.Context, tenant, tenderID, user string) (domain.TenderACL, error) {
	u := fmt.Sprintf("%s/internal/tenants/%s/tenders/%s/acl/%s",
		c.tenderACLBaseURL, url.PathEscape(tenant), url.PathEscape(tenderID), url.PathEscape(user))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return domain.TenderACL{}, fmt.Errorf("%w: build request: %v", ErrUnavailable, err)
	}
	gincommon.InjectTraceContext(ctx, req.Header)

	resp, err := c.tenderACLHTTP.Do(req)
	if err != nil {
		return domain.TenderACL{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// iam-tender-acl returns 400 for an invalid UUID or other caller-side
	// malformed request — this service's bug, not a transient dependency
	// outage. Map to ErrNotFound rather than ErrUnavailable as a defensive
	// forward guard: resolveTenderACL currently has no stale-if-error path
	// (any error fails closed to DenyTenderACLInsufficient), so the choice
	// of sentinel has no behavioral consequence today. If a stale-if-error
	// path is ever added to the tender-ACL overlay, ErrNotFound ensures a
	// caller-side 400 cannot activate it, while ErrUnavailable would.
	// 503 and all other non-2xx responses remain ErrUnavailable.
	switch resp.StatusCode {
	case http.StatusOK:
		// fall through to decode
	case http.StatusBadRequest:
		return domain.TenderACL{}, fmt.Errorf("%w: TAC-4 rejected the request (status 400 — check tender UUID format)", ErrNotFound)
	default:
		return domain.TenderACL{}, fmt.Errorf("%w: unexpected status %d", ErrUnavailable, resp.StatusCode)
	}

	var result domain.TenderACL
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return domain.TenderACL{}, fmt.Errorf("%w: decode response: %v", ErrUnavailable, err)
	}
	return result, nil
}

// batchCheckRequest/Response/item/resultDTO are the TAC-5 wire shapes.
// Kept package-private — callers use domain.BatchTenderACLItem/Result.
type batchCheckRequest struct {
	Items []batchCheckItemDTO `json:"items"`
}

type batchCheckItemDTO struct {
	TenderID string `json:"tender_id"`
	UserID   string `json:"user_id"`
}

type batchCheckResponse struct {
	Results []batchCheckResultDTO `json:"results"`
}

type batchCheckResultDTO struct {
	TenderID    string `json:"tender_id"`
	UserID      string `json:"user_id"`
	HasAccess   bool   `json:"has_access"`
	AccessLevel string `json:"access_level"`
	// ExpiresAt decoded as a plain string so an empty-string or null value
	// doesn't fail json.Unmarshal — converted to time.Time below.
	ExpiresAt string `json:"expires_at"`
}

// GetBatchTenderACL calls TAC-5 (iam-tender-acl §8.4 / TAC-D14):
// POST /internal/tenants/:id/acl/batch-check — no /api/v1 prefix, same as
// TAC-4. Replaces N individual GetTenderACL calls for dashboard-read paths
// (AE-30) that need to check many (tender, user) pairs in one tenant in a
// single round-trip. Same never-404/fail-closed posture as TAC-4 — a missing
// grant appears in the response as has_access:false, not an error. Callers
// must chunk requests larger than 50 items; iam-tender-acl enforces that cap.
func (c *Client) GetBatchTenderACL(ctx context.Context, tenant string, items []domain.BatchTenderACLItem) ([]domain.BatchTenderACLResult, error) {
	u := fmt.Sprintf("%s/internal/tenants/%s/acl/batch-check",
		c.tenderACLBaseURL, url.PathEscape(tenant))

	dtoItems := make([]batchCheckItemDTO, len(items))
	for i, item := range items {
		dtoItems[i] = batchCheckItemDTO{TenderID: item.TenderID, UserID: item.UserID}
	}
	// batchCheckRequest and batchCheckItemDTO contain only string/bool fields —
	// json.Marshal cannot fail for these types, so the error is discarded.
	body, _ := json.Marshal(batchCheckRequest{Items: dtoItems})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: build batch-check request: %v", ErrUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/json")
	gincommon.InjectTraceContext(ctx, req.Header)

	resp, err := c.tenderACLHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Mirror GetTenderACL's status classification: 400 (malformed batch
	// request — caller bug) → ErrNotFound so a stale-if-error path, if ever
	// added to a batch caller, cannot activate for a protocol error.
	if resp.StatusCode == http.StatusBadRequest {
		return nil, fmt.Errorf("%w: TAC-5 rejected the request (status 400 — check batch item format)", ErrNotFound)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: unexpected status %d", ErrUnavailable, resp.StatusCode)
	}

	var wireResp batchCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&wireResp); err != nil {
		return nil, fmt.Errorf("%w: decode batch-check response: %v", ErrUnavailable, err)
	}

	results := make([]domain.BatchTenderACLResult, len(wireResp.Results))
	for i, r := range wireResp.Results {
		results[i] = domain.BatchTenderACLResult{
			TenderID:    r.TenderID,
			UserID:      r.UserID,
			HasAccess:   r.HasAccess,
			AccessLevel: r.AccessLevel,
		}
		if r.ExpiresAt != "" {
			t, parseErr := time.Parse(time.RFC3339, r.ExpiresAt)
			if parseErr != nil {
				return nil, fmt.Errorf("%w: parse result[%d].expires_at %q: %v", ErrUnavailable, i, r.ExpiresAt, parseErr)
			}
			results[i].ExpiresAt = t
		}
	}
	return results, nil
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
	if err := c.getJSON(ctx, tenant, u, &resp); err != nil {
		return 0, err
	}
	return time.Duration(resp.MFAFreshnessSeconds) * time.Second, nil
}

// getJSON is used by the two Org & Membership calls (GetMemberships/
// GetMFAFreshness). Unlike iam-tender-acl's TAC-4 (mesh-only, no RBAC —
// GetTenderACL makes its request directly), Org & Membership's /internal/*
// routes are additionally gated by an application-level RequireSystemRole
// check that requires x-user-id/x-tenant-id/x-tenant-roles to be present
// on the request — verified directly against that service's own router
// (internal := v1.Group("/internal", RequireSystemRole())) and middleware
// (RequireSystemRole checks the request context carries the "iam-system"
// role, itself parsed from x-tenant-roles by GUCBridgeMiddleware). Every
// one of that service's own outbound clients to a sibling's internal API
// (catalogadmin, groupmappingclient, delegationcheck, workflow,
// realmprovisioner) sets these same three headers identically — this is
// the platform-wide internal-service-identity convention, not something
// specific to any one caller, so this client follows it too rather than
// inventing its own.
func (c *Client) getJSON(ctx context.Context, tenant, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrUnavailable, err)
	}
	req.Header.Set("x-user-id", "iam-system")
	req.Header.Set("x-tenant-id", tenant)
	req.Header.Set("x-tenant-roles", "iam-system")
	return c.doRequest(ctx, c.http, req, out)
}

func (c *Client) doRequest(ctx context.Context, httpClient *http.Client, req *http.Request, out any) error {
	gincommon.InjectTraceContext(ctx, req.Header)
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

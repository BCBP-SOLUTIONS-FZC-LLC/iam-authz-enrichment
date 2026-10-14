package orgmembership_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/gincommon"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/outbound/orgmembership"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// Contract test (§12): I-8's response must deserialize with list fields as
// an empty array, never null, even when the sibling service's JSON omits
// them entirely.
func TestGetMemberships_EmptyArraysNeverNull(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"plan": "pro",
			"subscription_status": "active",
			"read_only": false,
			"mfa_freshness_seconds": 300
		}`))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	membership, tenantCtx, err := client.GetMemberships(context.Background(), "tenant-1", "user-1")

	require.NoError(t, err)
	assert.NotNil(t, membership.Roles)
	assert.NotNil(t, membership.Departments)
	assert.Empty(t, membership.Roles)
	assert.Empty(t, membership.Departments)
	assert.NotNil(t, tenantCtx.FeatureFlags)
	assert.Empty(t, tenantCtx.FeatureFlags)
	assert.Equal(t, "pro", tenantCtx.Plan)
}

func TestGetMemberships_FullResponse_DecodesCorrectly(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"roles": ["tenant_admin"],
			"departments": [{"department_id": "eng", "role_level": "approver"}],
			"plan": "enterprise",
			"feature_flags": ["flag-a", "flag-b"],
			"subscription_status": "active",
			"read_only": false,
			"mfa_freshness_seconds": 300
		}`))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	membership, tenantCtx, err := client.GetMemberships(context.Background(), "tenant-1", "user-1")

	require.NoError(t, err)
	assert.Equal(t, []string{"tenant_admin"}, membership.Roles)
	assert.Equal(t, []domain.Department{{DepartmentID: "eng", Level: "approver"}}, membership.Departments)
	assert.Equal(t, "enterprise", tenantCtx.Plan)
	assert.Equal(t, []string{"flag-a", "flag-b"}, tenantCtx.FeatureFlags)
}

func TestGetMemberships_404_ReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, _, err := client.GetMemberships(context.Background(), "tenant-1", "user-1")

	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestGetMemberships_ServerError_ReturnsErrUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, _, err := client.GetMemberships(context.Background(), "tenant-1", "user-1")

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetMemberships_Timeout_ReturnsErrUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, 5*time.Millisecond, srv.URL, 5*time.Millisecond)
	_, _, err := client.GetMemberships(context.Background(), "tenant-1", "user-1")

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

// TenderACL (I-12) never returns 404 — absence of a grant is HasAccess:
// false, a normal decoded response, not an error.
func TestGetTenderACL_NoGrant_IsNotAnError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(domain.TenderACL{HasAccess: false})
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	acl, err := client.GetTenderACL(context.Background(), "tenant-1", "tender-1", "user-1")

	require.NoError(t, err)
	assert.False(t, acl.HasAccess)
}

func TestGetTenderACL_ServerError_ReturnsErrUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, err := client.GetTenderACL(context.Background(), "tenant-1", "tender-1", "user-1")

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetTenderACL_Timeout_ReturnsErrUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, 5*time.Millisecond, srv.URL, 5*time.Millisecond)
	_, err := client.GetTenderACL(context.Background(), "tenant-1", "tender-1", "user-1")

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetMFAFreshness_ServerError_ReturnsErrUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, err := client.GetMFAFreshness(context.Background(), "tenant-1")

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetMFAFreshness_Timeout_ReturnsErrUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, 5*time.Millisecond, srv.URL, 5*time.Millisecond)
	_, err := client.GetMFAFreshness(context.Background(), "tenant-1")

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetMemberships_MalformedBaseURL_RequestBuildError(t *testing.T) {
	t.Parallel()
	// A malformed base URL (invalid percent-encoding) makes
	// http.NewRequestWithContext itself fail, exercising getJSON's "build
	// request" error branch — distinct from a network/timeout failure.
	client := orgmembership.New("http://%zz", time.Second, "http://%zz", time.Second)
	_, _, err := client.GetMemberships(context.Background(), "tenant-1", "user-1")

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetTenderACL_MalformedBaseURL_RequestBuildError(t *testing.T) {
	t.Parallel()
	// Mirrors TestGetMemberships_MalformedBaseURL_RequestBuildError above,
	// but for getJSONWith's own "build request" branch (GetTenderACL is
	// the only caller that goes through getJSONWith directly rather than
	// getJSON).
	client := orgmembership.New("http://%zz", time.Second, "http://%zz", time.Second)
	_, err := client.GetTenderACL(context.Background(), "tenant-1", "tender-1", "user-1")

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetMemberships_MalformedJSONResponse_ReturnsErrUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, _, err := client.GetMemberships(context.Background(), "tenant-1", "user-1")

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetMemberships_PropagatesTraceparent(t *testing.T) {
	t.Parallel()
	shutdown := gincommon.InitTracingFromEnv()
	t.Cleanup(shutdown)

	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("traceparent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"plan":"pro","subscription_status":"active","read_only":false,"mfa_freshness_seconds":300}`))
	}))
	defer srv.Close()

	traceID, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	spanID, _ := trace.SpanIDFromHex("1112131415161718")
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	}))

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, _, err := client.GetMemberships(ctx, "tenant-1", "user-1")

	require.NoError(t, err)
	require.NotEmpty(t, got, "W3C traceparent must be injected via gincommon's propagator / otelhttp")
	assert.Contains(t, got, "0102030405060708090a0b0c0d0e0f10",
		"trace id must propagate; span id may be the otelhttp client span, not the parent")
}

// Org & Membership's /internal/* routes are gated by an application-level
// RequireSystemRole check requiring these three headers — without them,
// every real GetMemberships/GetMFAFreshness call 403s before ever reaching
// the handler, regardless of network/mTLS trust. This is the same
// "iam-system" convention every one of that service's own outbound
// sibling clients (catalogadmin, groupmappingclient, delegationcheck,
// workflow, realmprovisioner) uses.
func TestGetMemberships_SetsOrgMembershipInternalIdentityHeaders(t *testing.T) {
	t.Parallel()
	var userID, tenantID, tenantRoles string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID = r.Header.Get("x-user-id")
		tenantID = r.Header.Get("x-tenant-id")
		tenantRoles = r.Header.Get("x-tenant-roles")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"plan":"pro","subscription_status":"active","read_only":false,"mfa_freshness_seconds":300}`))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, _, err := client.GetMemberships(context.Background(), "tenant-acme", "alice")

	require.NoError(t, err)
	assert.Equal(t, "iam-system", userID)
	assert.Equal(t, "tenant-acme", tenantID)
	assert.Equal(t, "iam-system", tenantRoles)
}

func TestGetMFAFreshness_SetsOrgMembershipInternalIdentityHeaders(t *testing.T) {
	t.Parallel()
	var userID, tenantID, tenantRoles string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID = r.Header.Get("x-user-id")
		tenantID = r.Header.Get("x-tenant-id")
		tenantRoles = r.Header.Get("x-tenant-roles")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mfa_freshness_seconds":300}`))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, err := client.GetMFAFreshness(context.Background(), "tenant-acme")

	require.NoError(t, err)
	assert.Equal(t, "iam-system", userID)
	assert.Equal(t, "tenant-acme", tenantID)
	assert.Equal(t, "iam-system", tenantRoles)
}

// GetTenderACL (TAC-4) is mesh-only/no-RBAC on iam-tender-acl's side — it
// must NOT send these headers, so a future change can't accidentally imply
// TAC-4 has the same RBAC requirement Org & Membership's internal routes do.
func TestGetTenderACL_DoesNotSetOrgMembershipInternalIdentityHeaders(t *testing.T) {
	t.Parallel()
	var sawAny bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAny = r.Header.Get("x-user-id") != "" || r.Header.Get("x-tenant-roles") != ""
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"has_access":false}`))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, err := client.GetTenderACL(context.Background(), "tenant-acme", "tender-1", "alice")

	require.NoError(t, err)
	assert.False(t, sawAny, "TAC-4 is mesh-only/no-RBAC — it must never receive Org & Membership's internal-identity headers")
}

func TestGetMFAFreshness_DecodesSeconds(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mfa_freshness_seconds": 300}`))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	d, err := client.GetMFAFreshness(context.Background(), "tenant-1")

	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, d)
}

// GetTenderACL (TAC-4) resilience: iam-tender-acl omits expires_at when a
// grant has no expiry, but a misconfigured test double or future wire edge
// case might send "". The custom UnmarshalJSON on domain.TenderACL must treat
// that as zero time rather than a decode error that fails closed to
// DENY_TENDER_ACL_INSUFFICIENT on an otherwise-valid grant.
func TestGetTenderACL_EmptyExpiresAt_DoesNotError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"has_access":true,"access_level":"view","expires_at":""}`))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	acl, err := client.GetTenderACL(context.Background(), "tenant-1", "tender-1", "user-1")

	require.NoError(t, err)
	assert.True(t, acl.HasAccess)
	require.NotNil(t, acl.AccessLevel)
	assert.Equal(t, "view", *acl.AccessLevel)
	assert.True(t, acl.ExpiresAt.IsZero(), "empty expires_at must decode as zero time, not an error")
}

func TestGetTenderACL_NullExpiresAt_DoesNotError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"has_access":true,"access_level":"approve","expires_at":null}`))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	acl, err := client.GetTenderACL(context.Background(), "tenant-1", "tender-1", "user-1")

	require.NoError(t, err)
	assert.True(t, acl.HasAccess)
	assert.True(t, acl.ExpiresAt.IsZero(), "null expires_at must decode as zero time")
}

func TestGetTenderACL_WithExpiresAt_DecodesTime(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"has_access":true,"access_level":"edit","expires_at":"2026-12-31T23:59:59Z"}`))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	acl, err := client.GetTenderACL(context.Background(), "tenant-1", "tender-1", "user-1")

	require.NoError(t, err)
	assert.True(t, acl.HasAccess)
	require.NotNil(t, acl.AccessLevel)
	assert.Equal(t, "edit", *acl.AccessLevel)
	assert.Equal(t, 2026, acl.ExpiresAt.Year())
}

// TAC-5 (GetBatchTenderACL) tests.
func TestGetBatchTenderACL_HappyPath(t *testing.T) {
	t.Parallel()
	var gotMethod, gotPath, gotContentType string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[
			{"tender_id":"t1","user_id":"u1","has_access":true,"access_level":"approve","expires_at":"2026-12-31T00:00:00Z"},
			{"tender_id":"t2","user_id":"u1","has_access":false,"access_level":"","expires_at":""}
		]}`))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	results, err := client.GetBatchTenderACL(context.Background(), "tenant-acme", []domain.BatchTenderACLItem{
		{TenderID: "t1", UserID: "u1"},
		{TenderID: "t2", UserID: "u1"},
	})

	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/internal/tenants/tenant-acme/acl/batch-check", gotPath)
	assert.Equal(t, "application/json", gotContentType)
	assert.Contains(t, string(gotBody), `"tender_id":"t1"`)

	require.Len(t, results, 2)
	assert.True(t, results[0].HasAccess)
	assert.Equal(t, "approve", results[0].AccessLevel)
	assert.Equal(t, 2026, results[0].ExpiresAt.Year())

	assert.False(t, results[1].HasAccess)
	assert.True(t, results[1].ExpiresAt.IsZero(), "empty expires_at in batch result must be zero time")
}

func TestGetBatchTenderACL_ServerError_ReturnsErrUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, err := client.GetBatchTenderACL(context.Background(), "tenant-1", []domain.BatchTenderACLItem{
		{TenderID: "t1", UserID: "u1"},
	})

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetBatchTenderACL_Timeout_ReturnsErrUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, 5*time.Millisecond, srv.URL, 5*time.Millisecond)
	_, err := client.GetBatchTenderACL(context.Background(), "tenant-1", []domain.BatchTenderACLItem{
		{TenderID: "t1", UserID: "u1"},
	})

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetBatchTenderACL_MalformedResponse_ReturnsErrUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, err := client.GetBatchTenderACL(context.Background(), "tenant-1", []domain.BatchTenderACLItem{
		{TenderID: "t1", UserID: "u1"},
	})

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetBatchTenderACL_MalformedResponse_ReturnsErrUnavailableInline(t *testing.T) {
	t.Parallel()
	// Exercises the json.NewDecoder.Decode error path added when GetBatchTenderACL
	// gained its own inline status classification (the decode error branch
	// is separate from the existing TestGetBatchTenderACL_MalformedResponse test
	// only in code-path terms — this exercises the same decode branch but
	// after the new 400/non-2xx checks, confirming decode errors still map
	// to ErrUnavailable).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, err := client.GetBatchTenderACL(context.Background(), "tenant-1", []domain.BatchTenderACLItem{
		{TenderID: "t1", UserID: "u1"},
	})

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetBatchTenderACL_InvalidExpiresAtInResult_ReturnsErrUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[
			{"tender_id":"t1","user_id":"u1","has_access":true,"expires_at":"not-a-timestamp"}
		]}`))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, err := client.GetBatchTenderACL(context.Background(), "tenant-1", []domain.BatchTenderACLItem{
		{TenderID: "t1", UserID: "u1"},
	})

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetBatchTenderACL_MalformedBaseURL_RequestBuildError(t *testing.T) {
	t.Parallel()
	// Mirrors TestGetTenderACL_MalformedBaseURL_RequestBuildError for the
	// batch path — exercises the http.NewRequestWithContext "build batch-check
	// request" error branch in GetBatchTenderACL.
	client := orgmembership.New("http://%zz", time.Second, "http://%zz", time.Second)
	_, err := client.GetBatchTenderACL(context.Background(), "tenant-1", []domain.BatchTenderACLItem{
		{TenderID: "t1", UserID: "u1"},
	})

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetBatchTenderACL_DoesNotSetOrgMembershipInternalIdentityHeaders(t *testing.T) {
	t.Parallel()
	var sawAny bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAny = r.Header.Get("x-user-id") != "" || r.Header.Get("x-tenant-roles") != ""
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, err := client.GetBatchTenderACL(context.Background(), "tenant-acme", []domain.BatchTenderACLItem{
		{TenderID: "t1", UserID: "u1"},
	})

	require.NoError(t, err)
	assert.False(t, sawAny, "TAC-5 is mesh-only/no-RBAC — it must never receive Org & Membership's internal-identity headers")
}

// TAC-GAP-001: iam-tender-acl sends access_level with omitempty, so it is
// absent from the JSON when HasAccess is false. The decoded TenderACL must
// have a nil AccessLevel pointer (not an empty string) so the "no level
// granted" case is unambiguous and callers that inspect the pointer can
// distinguish absent from explicitly empty.
func TestGetTenderACL_MalformedJSONResponse_ReturnsErrUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, err := client.GetTenderACL(context.Background(), "tenant-1", "tender-1", "user-1")

	assert.ErrorIs(t, err, domain.ErrUnavailable)
}

func TestGetBatchTenderACL_400BadRequest_ReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, err := client.GetBatchTenderACL(context.Background(), "tenant-1", []domain.BatchTenderACLItem{
		{TenderID: "t1", UserID: "u1"},
	})

	assert.ErrorIs(t, err, domain.ErrNotFound,
		"TAC-5 400 must map to ErrNotFound (same as TAC-4) — stale-if-error must not activate for a caller-side error")
}

func TestGetTenderACL_AbsentAccessLevel_IsNil(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// TAC-4 wire shape when no grant: has_access false, access_level absent.
		_, _ = w.Write([]byte(`{"has_access":false}`))
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	acl, err := client.GetTenderACL(context.Background(), "tenant-1", "tender-1", "user-1")

	require.NoError(t, err)
	assert.False(t, acl.HasAccess)
	assert.Nil(t, acl.AccessLevel, "absent access_level on the wire must decode as nil, not empty string (TAC-GAP-001)")
	assert.False(t, acl.Satisfies(domain.AccessLevelView), "nil AccessLevel must never satisfy any level")
}

// TAC-GAP-005: a TAC-4 HTTP 400 (invalid UUID / bad request) is a caller-side
// bug, not a transient outage. It must map to ErrNotFound so the §7
// stale-if-error path is not activated — stale-if-error is for transient
// dependency outages (ErrUnavailable), not for protocol errors caused by
// a malformed request from this service.
func TestGetTenderACL_400BadRequest_ReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, err := client.GetTenderACL(context.Background(), "tenant-1", "tender-1", "user-1")

	assert.ErrorIs(t, err, domain.ErrNotFound,
		"TAC-4 400 must map to ErrNotFound, not ErrUnavailable — stale-if-error must not activate for a caller-side error")
}

func TestGetTenderACL_503ServiceUnavailable_ReturnsErrUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := orgmembership.New(srv.URL, time.Second, srv.URL, time.Second)
	_, err := client.GetTenderACL(context.Background(), "tenant-1", "tender-1", "user-1")

	assert.ErrorIs(t, err, domain.ErrUnavailable,
		"TAC-4 503 must map to ErrUnavailable so §7 stale-if-error can activate for a real dependency outage")
}

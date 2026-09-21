package orgmembership_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

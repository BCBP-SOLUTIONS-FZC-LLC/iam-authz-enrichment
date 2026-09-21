//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// departmentFixture/membershipFixture/tenderACLFixture mirror the exact
// wire shapes internal/adapter/outbound/orgmembership/client.go decodes
// (departmentDTO/membershipsResponse/GetTenderACL's response) — see that
// file for the field-tag history (LLD §16 AE-25 renamed Level -> role_level
// after a real wire-format mismatch slipped past every mock that didn't
// use these exact tags).
type departmentFixture struct {
	DepartmentID string `json:"department_id"`
	Level        string `json:"role_level"`
}

type membershipFixture struct {
	Roles               []string            `json:"roles"`
	Departments         []departmentFixture `json:"departments"`
	Plan                string              `json:"plan"`
	FeatureFlags        []string            `json:"feature_flags"`
	SubscriptionStatus  string              `json:"subscription_status"`
	ReadOnly            bool                `json:"read_only"`
	MFAFreshnessSeconds int                 `json:"mfa_freshness_seconds"`
}

// ExpiresAt is a real time.Time, not a string — the real client
// (client.go's GetTenderACL) decodes directly into domain.TenderACL, whose
// ExpiresAt field is time.Time; an empty string there fails
// encoding/json's time.Time unmarshal, which is silently indistinguishable
// from every other GetTenderACL error and fails closed to
// DENY_TENDER_ACL_INSUFFICIENT (§7's fail-closed-for-the-overlay-only
// rule) — a mock bug that looks exactly like a real denial, caught by this
// suite's own TestTenderACLOverlay_FullFlow before this fix.
type tenderACLFixture struct {
	HasAccess   bool      `json:"has_access"`
	AccessLevel string    `json:"access_level"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// fakeOrg fakes both Org & Membership (I-8 memberships, I-14 mfa-freshness)
// and the Tender ACL Service (TAC-4) — this service's own client folds both
// into one outbound package, so one fake HTTP server covers both, same as
// README.md's "Seeing an Allow decision" / "Testing the tender-ACL overlay"
// manual walkthroughs reuse one mock server for both.
//
// Named fakeOrg/fakeorg.go, not mockOrg/mockorg.go: this repo's .gitignore
// has a `mockorg*` rule (README's own throwaway local mockorg/ directory
// for the manual grpcurl walkthrough) that glob-matches any path containing
// that basename anywhere in the tree, not just at the repo root — a file
// named mockorg.go here was silently excluded from every `git add`, built
// and ran fine locally (go test reads the working directory regardless of
// git tracking), and only broke in CI's fresh checkout. "Fake" also matches
// this codebase's existing test-double convention (test/fixtures' FakeCache).
type fakeOrg struct {
	mu           sync.Mutex
	memberships  map[string]membershipFixture // key: tenant+"/"+user
	mfaFreshness map[string]int               // key: tenant
	tenderACL    map[string]tenderACLFixture  // key: tenant+"/"+tender+"/"+user

	server *httptest.Server
}

func newFakeOrg() *fakeOrg {
	m := &fakeOrg{
		memberships:  map[string]membershipFixture{},
		mfaFreshness: map[string]int{},
		tenderACL:    map[string]tenderACLFixture{},
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.route))
	return m
}

func (m *fakeOrg) URL() string { return m.server.URL }
func (m *fakeOrg) Close()      { m.server.Close() }

func (m *fakeOrg) setMembership(tenant, user string, f membershipFixture) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.memberships[tenant+"/"+user] = f
}

func (m *fakeOrg) setMFAFreshness(tenant string, seconds int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mfaFreshness[tenant] = seconds
}

func (m *fakeOrg) setTenderACL(tenant, tender, user string, f tenderACLFixture) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenderACL[tenant+"/"+tender+"/"+user] = f
}

// route dispatches the three paths client.go actually calls — see that
// file's doc comments for the exact confirmed shapes (§16 AE-19's TAC-4
// confirmation, §16 AE-16's I-14 confirmation).
func (m *fakeOrg) route(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch {
	case strings.HasPrefix(r.URL.Path, "/api/v1/internal/users/") && strings.HasSuffix(r.URL.Path, "/memberships"):
		// GET /api/v1/internal/users/:id/memberships?tenant_id=... (I-8)
		user := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/internal/users/"), "/memberships")
		tenant := r.URL.Query().Get("tenant_id")
		f, ok := m.memberships[tenant+"/"+user]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, f)

	case strings.HasPrefix(r.URL.Path, "/api/v1/internal/tenants/") && strings.HasSuffix(r.URL.Path, "/mfa-freshness"):
		// GET /api/v1/internal/tenants/:id/mfa-freshness (I-14)
		tenant := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/internal/tenants/"), "/mfa-freshness")
		seconds, ok := m.mfaFreshness[tenant]
		if !ok {
			seconds = 300 // sane default for scenarios that don't exercise the MFA gate
		}
		writeJSON(w, map[string]any{"mfa_freshness_seconds": seconds, "tenant_id": tenant})

	case strings.HasPrefix(r.URL.Path, "/internal/tenants/"):
		// GET /internal/tenants/:id/tenders/:tender_id/acl/:user_id (TAC-4,
		// no /api/v1 prefix — confirmed §16 AE-19). Never 404s: a no-grant
		// answer is 200 OK with has_access:false.
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/internal/tenants/"), "/")
		if len(parts) != 5 || parts[1] != "tenders" || parts[3] != "acl" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		tenant, tender, user := parts[0], parts[2], parts[4]
		f, ok := m.tenderACL[tenant+"/"+tender+"/"+user]
		if !ok {
			f = tenderACLFixture{HasAccess: false}
		}
		writeJSON(w, f)

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

package domain_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// DenyReasons() is hand-kept; this test parses every non-test file in the
// domain package and fails if a DenyReason const is missing from it (or
// listed twice), so a new reason cannot silently skip the deny-codes.json,
// metrics and cache tests.
func TestDenyReasons_CoversEveryConst(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	var consts []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		require.NoError(t, err)
		for _, decl := range f.Decls {
			g, ok := decl.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			for _, spec := range g.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, v := range vs.Values {
					lit, ok := denyReasonLiteral(vs.Type, v)
					if !ok {
						continue
					}
					s, err := strconv.Unquote(lit.Value)
					require.NoError(t, err, "%s: const %s", name, vs.Names[i].Name)
					consts = append(consts, s)
				}
			}
		}
	}
	require.NotEmpty(t, consts, "found no DenyReason consts; has the declaration style changed?")
	got := make([]string, 0, len(domain.DenyReasons()))
	for _, r := range domain.DenyReasons() {
		got = append(got, string(r))
	}
	assert.ElementsMatch(t, consts, got, "DenyReasons() must list every DenyReason const exactly once")
}

// TestDenyReasons_CoversEveryConst only reads the domain package. This test
// covers the rest of internal/: a reason made up inline elsewhere, such as
// domain.DenyReason("DENY_X") in usecase, would skip DenyReasons(),
// deny-codes.json and denyDetails, so it is not allowed.
func TestDenyReason_NoLiteralsOutsideDomain(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(`DenyReason\(\s*"`)
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		if filepath.Dir(path) == filepath.Join("..", "domain") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		assert.False(t, re.Match(src), "%s builds a DenyReason from a string literal; declare it in internal/domain instead", path)
		return nil
	})
	require.NoError(t, err)
}

// denyReasonLiteral returns the string literal of a DenyReason const,
// written either as `X DenyReason = "..."` or as `X = DenyReason("...")`.
func denyReasonLiteral(typ ast.Expr, v ast.Expr) (*ast.BasicLit, bool) {
	if id, ok := typ.(*ast.Ident); ok && id.Name == "DenyReason" {
		lit, ok := v.(*ast.BasicLit)
		return lit, ok && lit.Kind == token.STRING
	}
	call, ok := v.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return nil, false
	}
	if fn, ok := call.Fun.(*ast.Ident); !ok || fn.Name != "DenyReason" {
		return nil, false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	return lit, ok && lit.Kind == token.STRING
}

func TestNegativeCacheReason(t *testing.T) {
	t.Parallel()
	assert.Equal(t, domain.DenyMemberSuspended, domain.NegativeCacheReason("DENY_MEMBER_SUSPENDED"))
	for _, v := range []string{"1", "", "DENY_UNRESOLVABLE_SUBJECT", "DENY_SERVICE_UNAVAILABLE", "DENY_MALFORMED_IDENTITY", "junk"} {
		assert.Equal(t, domain.DenyUnresolvableSubject, domain.NegativeCacheReason(v), v)
	}
}

func TestDenyReason_HTTPStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		reason domain.DenyReason
		status int
	}{
		{domain.DenyUnresolvableSubject, 403},
		{domain.DenyMemberSuspended, 403},
		{domain.DenyTenantReadOnly, 403},
		{domain.DenyMFAStale, 403},
		{domain.DenyTenderACLInsufficient, 403},
		{domain.DenyRoleInsufficient, 403},
		{domain.DenyServiceUnavailable, 503},
		{domain.DenyMalformedIdentity, 401},
	}
	for _, c := range cases {
		assert.Equal(t, c.status, c.reason.HTTPStatus(), "reason %s", c.reason)
	}
}

func TestTenderACL_Satisfies(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		acl      domain.TenderACL
		required string
		want     bool
	}{
		{"no access never satisfies", domain.TenderACL{HasAccess: false, AccessLevel: strPtr(domain.AccessLevelApprove)}, domain.AccessLevelView, false},
		{"view satisfies view", domain.TenderACL{HasAccess: true, AccessLevel: strPtr(domain.AccessLevelView)}, domain.AccessLevelView, true},
		{"view does not satisfy edit", domain.TenderACL{HasAccess: true, AccessLevel: strPtr(domain.AccessLevelView)}, domain.AccessLevelEdit, false},
		{"approve satisfies view", domain.TenderACL{HasAccess: true, AccessLevel: strPtr(domain.AccessLevelApprove)}, domain.AccessLevelView, true},
		{"approve satisfies edit", domain.TenderACL{HasAccess: true, AccessLevel: strPtr(domain.AccessLevelApprove)}, domain.AccessLevelEdit, true},
		{"unrecognized granted level never satisfies", domain.TenderACL{HasAccess: true, AccessLevel: strPtr("bogus")}, domain.AccessLevelView, false},
		{"unrecognized required level never satisfies", domain.TenderACL{HasAccess: true, AccessLevel: strPtr(domain.AccessLevelApprove)}, "bogus", false},
		{"nil access level never satisfies (absent on wire — TAC-GAP-001)", domain.TenderACL{HasAccess: true, AccessLevel: nil}, domain.AccessLevelView, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, c.want, c.acl.Satisfies(c.required))
		})
	}
}

func strPtr(s string) *string { return &s }

func TestTenderACL_UnmarshalJSON_InvalidJSON_ReturnsError(t *testing.T) {
	t.Parallel()
	var acl domain.TenderACL
	err := acl.UnmarshalJSON([]byte("not-json"))
	assert.Error(t, err, "completely invalid JSON must propagate a parse error")
}

func TestTenderACL_UnmarshalJSON_InvalidExpiresAt_ReturnsError(t *testing.T) {
	t.Parallel()
	var acl domain.TenderACL
	err := acl.UnmarshalJSON([]byte(`{"has_access":true,"expires_at":"not-a-timestamp"}`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expires_at")
}

func TestDenyReason_HTTPStatus_UnknownReasonDefaultsTo403(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 403, domain.DenyReason("bogus").HTTPStatus())
}

func TestAllowed_BuildsAllowDecisionWithHeaders(t *testing.T) {
	t.Parallel()
	headers := map[string]string{domain.HeaderTenantID: "t1"}
	d := domain.Allowed(headers)
	assert.True(t, d.Allow)
	assert.Equal(t, headers, d.Headers)
	assert.Empty(t, d.Reason)
}

func TestDenied_BuildsDenyDecisionWithReason(t *testing.T) {
	t.Parallel()
	d := domain.Denied(domain.DenyRoleInsufficient)
	assert.False(t, d.Allow)
	assert.Equal(t, domain.DenyRoleInsufficient, d.Reason)
	assert.Empty(t, d.Headers)
}

func TestNewMembershipContext_EmptyListsNeverNil(t *testing.T) {
	t.Parallel()
	m := domain.NewMembershipContext()
	assert.NotNil(t, m.Roles)
	assert.NotNil(t, m.Departments)
	assert.Empty(t, m.Roles)
	assert.Empty(t, m.Departments)
}

func TestNewTenantContext_EmptyListsNeverNil(t *testing.T) {
	t.Parallel()
	tc := domain.NewTenantContext()
	assert.NotNil(t, tc.FeatureFlags)
	assert.Empty(t, tc.FeatureFlags)
}

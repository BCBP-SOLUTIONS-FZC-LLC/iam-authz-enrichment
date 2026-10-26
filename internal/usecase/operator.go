package usecase

import (
	"strings"

	"github.com/google/uuid"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

// operatorTenantsSegment precedes the tenant id in tenant-scoped operator
// routes, e.g. /api/v1/operator/tenants/{id}/entitlement-overrides/{key}.
const operatorTenantsSegment = "tenants/"

// isOperatorToken reports whether claims came from the platform realm.
// An empty OperatorIssuer disables the operator path: such tokens then fail
// tenant resolution exactly as before (DENY_MALFORMED_IDENTITY).
func (c *Checker) isOperatorToken(claims Claims) bool {
	return c.cfg.OperatorIssuer != "" && claims.Issuer == c.cfg.OperatorIssuer
}

// checkOperator is the CD-52 operator path (LLD §8.9). A platform-realm token:
//
//  1. may reach /api/v1/operator/* only — anywhere else is DENY_ROLE_INSUFFICIENT,
//     so an operator token can never act as a tenant user;
//  2. must carry the platform_operator realm role;
//  3. must have a UUID subject, since every service parses x-user-id as one;
//  4. gets x-tenant-id from the path for /api/v1/operator/tenants/{id}/…, or
//     the nil-UUID sentinel for operator routes that name no tenant. A
//     malformed tenant segment is DENY_MALFORMED_IDENTITY, like the tender
//     path guard in check().
//
// No membership or tenant context is resolved — an operator is not a tenant
// member — so x-departments, x-plan, x-feature-flags and x-residency-mode are
// sent empty, overwriting any client copy. Every operator decision is logged
// with the operator's subject and the target tenant (the operator audit
// trail, LLD §10).
func (c *Checker) checkOperator(in CheckInput) domain.Decision {
	path := in.Request.Path
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	decision := c.operatorDecision(in.Claims, path)
	fields := map[string]interface{}{
		"operator_sub": in.Claims.Subject,
		"method":       in.Request.Method,
		"path":         path,
		"allowed":      decision.Allow,
	}
	if decision.Allow {
		fields["tenant"] = decision.Headers[domain.HeaderTenantID]
	} else {
		fields["reason"] = string(decision.Reason)
	}
	c.log.Info("operator_access", fields)
	return decision
}

func (c *Checker) operatorDecision(claims Claims, path string) domain.Decision {
	if !strings.HasPrefix(path, domain.OperatorRoutePrefix) {
		return domain.Denied(domain.DenyRoleInsufficient)
	}
	if !hasRole(claims.Roles, domain.PlatformOperatorRole) {
		return domain.Denied(domain.DenyRoleInsufficient)
	}
	if _, err := uuid.Parse(claims.Subject); err != nil {
		return domain.Denied(domain.DenyMalformedIdentity)
	}
	tenant, ok := operatorTenantFromPath(path)
	if !ok {
		return domain.Denied(domain.DenyMalformedIdentity)
	}
	return domain.Allowed(map[string]string{
		domain.HeaderTenantID:      tenant,
		domain.HeaderUserID:        claims.Subject,
		domain.HeaderTenantRoles:   domain.PlatformOperatorRole,
		domain.HeaderDepartments:   "",
		domain.HeaderPlan:          "",
		domain.HeaderFeatureFlags:  "",
		domain.HeaderResidencyMode: "",
	})
}

// operatorTenantFromPath returns the tenant an operator route acts on: the
// UUID after /api/v1/operator/tenants/, or NilTenantID when the route names
// no tenant. ok is false when the tenants/ segment is present but not a UUID.
func operatorTenantFromPath(path string) (string, bool) {
	rest := strings.TrimPrefix(path, domain.OperatorRoutePrefix)
	after, found := strings.CutPrefix(rest, operatorTenantsSegment)
	if !found {
		return domain.NilTenantID, true
	}
	id, _, _ := strings.Cut(after, "/")
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil {
		return "", false
	}
	return parsed.String(), true
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

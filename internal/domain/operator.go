package domain

// Operator path (CD-52, LLD §8.9). Platform operators sign in to a dedicated
// platform realm — never a tenant realm — and reach only /api/v1/operator/*.
const (
	// PlatformOperatorRole is the platform-realm role every service's
	// operator routes check (RequireOperatorRole). It is the only operator
	// role this service currently recognises; it is injected in
	// x-tenant-roles, the header those checks read.
	PlatformOperatorRole = "platform_operator"

	// OperatorRoutePrefix is the only path prefix an operator token may
	// reach. A platform-realm token anywhere else is denied, and a tenant
	// token here gains nothing, because only the operator path ever injects
	// PlatformOperatorRole.
	OperatorRoutePrefix = "/api/v1/operator/"

	// NilTenantID is x-tenant-id on an operator route that names no tenant
	// (e.g. /api/v1/operator/billing/reconciliation-runs) — the same
	// uuid.Nil sentinel the IAM services already use for cross-tenant calls
	// (IAM HLD §7.2).
	NilTenantID = "00000000-0000-0000-0000-000000000000"
)

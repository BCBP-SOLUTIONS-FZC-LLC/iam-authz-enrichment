package domain

// Operator path (CD-52, LLD §8.9). Platform operators sign in to a dedicated
// platform realm — never a tenant realm — and reach only /api/v1/operator/*.
const (
	// PlatformOperatorRole is the platform-realm role an operator token must
	// carry to reach /api/v1/operator/* (gate check in operatorDecision).
	// All platform-realm roles — including pci_owner_reviewer (A-10, BL-OQ-26)
	// — are forwarded in x-tenant-roles so downstream services can gate on
	// them; PlatformOperatorRole just controls the entry gate here.
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

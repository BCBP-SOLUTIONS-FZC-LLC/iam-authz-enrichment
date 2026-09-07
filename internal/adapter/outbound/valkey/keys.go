package valkey

import "fmt"

// Key schema from LLD §4.1. Every key is tenant-scoped by construction
// (§8.4) — there is no shared, unscoped namespace anywhere in this package.

func ctxKey(tenant, user string) string {
	return fmt.Sprintf("ae:ctx:%s:%s", tenant, user)
}

// tenantKey is the tenant-scoped slice (plan/feature_flags/subscription_status/
// read_only), split out from ctxKey by construction (§4.1) so a tenant-wide
// event is always a single-key eviction, never a SCAN.
func tenantKey(tenant string) string {
	return fmt.Sprintf("ae:tenant:%s", tenant)
}

func tenderACLKey(tenant, tender, user string) string {
	return fmt.Sprintf("ae:tender_acl:%s:%s:%s", tenant, tender, user)
}

// tenderACLUserPattern matches every tender-ACL entry for a user across all
// tenders/tenders — used only for the UserDeleted best-effort SCAN+delete
// (§5: "ae:tender_acl:{tenant}:*:{user}").
func tenderACLUserPattern(tenant, user string) string {
	return fmt.Sprintf("ae:tender_acl:%s:*:%s", tenant, user)
}

func negativeKey(tenant, user string) string {
	return fmt.Sprintf("ae:neg:%s:%s", tenant, user)
}

func processedKey(eventID string) string {
	return fmt.Sprintf("ae:processed:%s", eventID)
}

func realmKey(realm string) string {
	return fmt.Sprintf("ae:realm:%s", realm)
}

func restrictedFactKey(tenant, tender string) string {
	return fmt.Sprintf("ae:restricted:%s:%s", tenant, tender)
}

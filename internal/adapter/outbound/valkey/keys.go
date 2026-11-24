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

// subjectGenKey is the per-(tenant,user) write guard (§4.1, §16 AE-51) for
// ae:ctx, ae:neg and ae:tender_acl: a random token that every
// EvictMembershipContext, EvictNegative, EvictTenderACL and
// EvictTenderACLForUser replaces, so a rebuild that started before an
// eviction cannot write its older answer back. A new eviction of any of
// those keys must replace it too. The "ae:gen:" prefix keeps it out of any
// ae:ctx / ae:neg / ae:tender_acl pattern.
func subjectGenKey(tenant, user string) string {
	return fmt.Sprintf("ae:gen:%s:%s", tenant, user)
}

// tenantGenKey is the same write guard for the tenant-wide ae:tenant entry,
// replaced by every EvictTenantContext.
func tenantGenKey(tenant string) string {
	return fmt.Sprintf("ae:tgen:%s", tenant)
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

// restrictedTenantPattern matches every restricted-tender entry for a tenant —
// used only for the TenantOffboarded full-cleanup SCAN+delete (§5).
func restrictedTenantPattern(tenant string) string {
	return fmt.Sprintf("ae:restricted:%s:*", tenant)
}

// realmByTenantKey is the reverse-index key for the tenant→realm mapping.
// Stored as a Redis Set; members are the realm issuer URLs that map to this
// tenant. Written alongside ae:realm:{issuer} by SetRealm so that
// EvictRealmsByTenant can look up a tenant's realms in O(1) instead of
// scanning the entire ae:realm:* keyspace.
func realmByTenantKey(tenant string) string {
	return fmt.Sprintf("ae:realm-by-tenant:%s", tenant)
}

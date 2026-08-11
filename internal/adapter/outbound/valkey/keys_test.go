package valkey

import "testing"

// Pure key-construction tests — no Valkey needed. Tenant-scoping-by-
// construction (§8.4) means every key must embed both tenant and, where
// applicable, user — these tests pin the exact §4.1 key schema so a future
// change can't silently drift the format (which would orphan existing cache
// entries or, worse, collide across tenants).

func TestCtxKey(t *testing.T) {
	if got, want := ctxKey("tenant-1", "user-1"), "ae:ctx:tenant-1:user-1"; got != want {
		t.Errorf("ctxKey() = %q, want %q", got, want)
	}
}

func TestTenantKey(t *testing.T) {
	if got, want := tenantKey("tenant-1"), "ae:tenant:tenant-1"; got != want {
		t.Errorf("tenantKey() = %q, want %q", got, want)
	}
}

func TestTenderACLKey(t *testing.T) {
	if got, want := tenderACLKey("tenant-1", "tender-9", "user-1"), "ae:tender_acl:tenant-1:tender-9:user-1"; got != want {
		t.Errorf("tenderACLKey() = %q, want %q", got, want)
	}
}

func TestTenderACLUserPattern(t *testing.T) {
	if got, want := tenderACLUserPattern("tenant-1", "user-1"), "ae:tender_acl:tenant-1:*:user-1"; got != want {
		t.Errorf("tenderACLUserPattern() = %q, want %q", got, want)
	}
}

func TestNegativeKey(t *testing.T) {
	if got, want := negativeKey("tenant-1", "user-1"), "ae:neg:tenant-1:user-1"; got != want {
		t.Errorf("negativeKey() = %q, want %q", got, want)
	}
}

func TestProcessedKey(t *testing.T) {
	if got, want := processedKey("evt-123"), "ae:processed:evt-123"; got != want {
		t.Errorf("processedKey() = %q, want %q", got, want)
	}
}

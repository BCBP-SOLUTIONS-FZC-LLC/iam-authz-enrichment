package main

import (
	"context"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/outbound/valkey"
)

// factStore is the store RealmMap and RestrictedTenderSet are bound to. They
// are shared by both paths: the request path only reads them (GetRealm /
// GetRestricted), the SQS consumers and startup seeding only write them
// (SetRealm / SetRestricted). Reads go through the request-path Cache and its
// single-digit-ms timeouts; the two writes go through writes, the event
// Cache with VALKEY_EVENT_TIMEOUT — so a TenderRestricted fact isn't lost to
// a momentary Valkey blip and retried a full SQS visibility timeout later.
type factStore struct {
	*valkey.Cache
	writes *valkey.Cache
}

func (s factStore) SetRealm(ctx context.Context, realm, tenant string) error {
	return s.writes.SetRealm(ctx, realm, tenant)
}

func (s factStore) SetRestricted(ctx context.Context, tenant, tender string) error {
	return s.writes.SetRestricted(ctx, tenant, tender)
}

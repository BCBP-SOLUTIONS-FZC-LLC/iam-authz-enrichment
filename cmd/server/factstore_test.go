package main

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/outbound/valkey"
)

// factStore writes through the event Cache and reads through the request
// Cache. Proven by pointing the two at different Valkeys.
func TestFactStore_RoutesWritesToEventCache(t *testing.T) {
	reqMR, evMR := miniredis.RunT(t), miniredis.RunT(t)
	req := valkey.New(valkey.Config{Addr: reqMR.Addr(), ReadTimeout: time.Second})
	ev := valkey.New(valkey.Config{Addr: evMR.Addr(), ReadTimeout: time.Second})
	t.Cleanup(func() { _ = req.Close(); _ = ev.Close() })
	s := factStore{Cache: req, writes: ev}
	ctx := context.Background()

	require.NoError(t, s.SetRestricted(ctx, "t1", "td1"))
	require.NoError(t, s.SetRealm(ctx, "https://kc/realms/acme", "t1"))
	assert.Len(t, evMR.Keys(), 2, "both writes go to the event Cache")
	assert.Empty(t, reqMR.Keys(), "nothing is written through the request Cache")

	got, err := s.GetRestricted(ctx, "t1", "td1")
	require.NoError(t, err)
	assert.False(t, got, "reads go through the request Cache")
}

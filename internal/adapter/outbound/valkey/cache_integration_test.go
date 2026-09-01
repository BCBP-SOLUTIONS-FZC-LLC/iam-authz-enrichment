//go:build integration

package valkey

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func integrationAddr() string {
	if v := os.Getenv("VALKEY_URL"); v != "" {
		return v
	}
	return "localhost:6379"
}

// failAfterNDelsHook allows the first n DEL commands to succeed and fails
// every subsequent one. Used to simulate the TC-054 scenario: the first
// SCAN page's keys are deleted, but DEL for the second page's batch fails,
// producing a partial eviction and an error return.
type failAfterNDelsHook struct {
	n     int64
	count atomic.Int64
}

func (h *failAfterNDelsHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *failAfterNDelsHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *failAfterNDelsHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "del" && h.count.Add(1) > h.n {
			return errors.New("simulated DEL failure on second SCAN page")
		}
		return next(ctx, cmd)
	}
}

// TC-054: multi-page SCAN where DEL succeeds on the first page but fails on
// the second — EvictTenderACLForUser must propagate the error. With real
// Valkey and COUNT=100, 200 keys guarantee at least two SCAN pages.
func TestEvictTenderACLForUser_DelFailsOnSecondPage_PartialEviction(t *testing.T) {
	addr := integrationAddr()
	const numKeys = 200
	tenant, user := "tc054-tenant", "tc054-user"

	// Use a plain client to seed data and clean up without the failure hook.
	seed := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = seed.Close() })
	require.NoError(t, seed.Ping(context.Background()).Err(),
		"Valkey must be reachable — run `docker compose up -d valkey`")

	ctx := context.Background()
	t.Cleanup(func() {
		for i := range numKeys {
			_ = seed.Del(ctx, tenderACLKey(tenant, fmt.Sprintf("tender-%d", i), user))
		}
	})
	for i := range numKeys {
		require.NoError(t, seed.Set(ctx,
			tenderACLKey(tenant, fmt.Sprintf("tender-%d", i), user),
			`{"has_access":true}`,
			time.Hour,
		).Err())
	}

	// Hooked client: allows first DEL batch (one SCAN page), fails the second.
	hook := &failAfterNDelsHook{n: 1}
	hooked := redis.NewClient(&redis.Options{Addr: addr})
	hooked.AddHook(hook)
	t.Cleanup(func() { _ = hooked.Close() })

	c := &Cache{client: hooked, tenderACLTTL: time.Hour}

	err := c.EvictTenderACLForUser(ctx, tenant, user)
	assert.Error(t, err, "DEL failure on second SCAN page must propagate as an error (partial eviction)")
}

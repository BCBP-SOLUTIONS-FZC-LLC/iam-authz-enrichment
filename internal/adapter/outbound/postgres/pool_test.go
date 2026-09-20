package postgres

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-pgcommon/pkg/pgcommon"
)

func TestPoolConfig_WiresLoggerTracerNoGUC(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@h:5432/db?sslmode=disable")
	t.Setenv("PG_MAX_CONNS", "20")
	rec := &recordingLogger{}

	cfg, _ := PoolConfig(rec, "iam-authz-enrichment-test")
	assert.Equal(t, "postgres://u:p@h:5432/db?sslmode=disable", cfg.DSN)
	assert.Nil(t, cfg.GUCProvider, "this service has no RLS tables")
	assert.NotNil(t, cfg.Logger)
	assert.NotNil(t, cfg.Tracer)
	assert.Equal(t, int32(20), cfg.MaxConns)
}

func TestPoolConfig_NilLoggerLeavesLoggerUnset(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PG_USER", "")
	t.Setenv("PG_DBNAME", "")

	cfg, warnings := PoolConfig(nil, "iam-authz-enrichment-test")
	assert.Nil(t, cfg.Logger)
	assert.NotNil(t, cfg.Tracer)
	assert.Empty(t, cfg.DSN)
	found := false
	for _, w := range warnings {
		if w.Key == "PG_USER/PG_DBNAME" {
			found = true
			break
		}
	}
	assert.True(t, found, "empty DSN should surface the ConfigFromEnv missing-user/dbname warning")
}

func TestOpenPool_EmptyDSN(t *testing.T) {
	_, err := OpenPool(context.Background(), pgcommon.Config{})
	require.Error(t, err)
}

func TestSystemPoolConfig_ForcesPGBouncerMode(t *testing.T) {
	t.Setenv("PG_BOUNCER_MODE", "false")
	t.Setenv("PG_MAX_CONNS", "20")
	t.Setenv("PG_STATEMENT_TIMEOUT", "")

	cfg := SystemPoolConfig("postgres://sys@host/db", nil)
	assert.Equal(t, "postgres://sys@host/db", cfg.DSN)
	assert.True(t, cfg.PGBouncerMode)
	assert.Nil(t, cfg.GUCProvider)
	assert.Nil(t, cfg.Tracer)
	assert.Nil(t, cfg.Logger)
	assert.Equal(t, int32(20), cfg.MaxConns)
}

func TestSystemPoolConfig_NonNilLoggerWiresAdapter(t *testing.T) {
	t.Setenv("PG_STATEMENT_TIMEOUT", "")
	cfg := SystemPoolConfig("postgres://sys@host/db", &recordingLogger{})
	assert.NotNil(t, cfg.Logger)
}

func TestSystemPoolConfig_AppliesStatementTimeout(t *testing.T) {
	t.Setenv("PG_STATEMENT_TIMEOUT", "5s")
	cfg := SystemPoolConfig("postgres://sys@host/db?sslmode=disable", nil)
	assert.Contains(t, cfg.DSN, "statement_timeout%3D5000")
}

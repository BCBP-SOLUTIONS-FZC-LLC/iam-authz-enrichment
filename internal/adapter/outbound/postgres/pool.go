package postgres

import (
	"context"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-pgcommon/v2/pkg/pgcommon"
)

// PoolConfig builds the pgcommon.Config siblings pass to NewPool:
// ConfigFromEnv for pool sizing / PG_BOUNCER_MODE / slow-query threshold,
// DSNFromEnv (adds PG_STATEMENT_TIMEOUT on the PG_* path), Zap via
// NewLoggerAdapter, and gincommon's TracerProvider via NewOTelTracer.
// GUCProvider is left nil — this service has no RLS tables.
func PoolConfig(log Logger, serviceName string) (pgcommon.Config, []pgcommon.ConfigWarning) {
	cfg, warnings := pgcommon.ConfigFromEnv()
	cfg.DSN = DSNFromEnv()
	cfg.GUCProvider = nil
	cfg.Tracer = NewOTelTracer(serviceName)
	if log != nil {
		cfg.Logger = NewLoggerAdapter(log)
	} else {
		cfg.Logger = nil
	}
	return cfg, warnings
}

// SystemPoolConfig returns pgcommon.Config for a BYPASSRLS system pool,
// matching iam-user-profile / iam-org-membership: ConfigFromEnv pool
// sizing, no GUCProvider, PGBouncerMode forced true, Tracer left unset
// (call sites wire NewOTelTracer). cmd/server does not open this pool.
func SystemPoolConfig(dsn string, log Logger) pgcommon.Config {
	cfg, _ := pgcommon.ConfigFromEnv()
	cfg.DSN = ApplyStatementTimeout(dsn)
	cfg.GUCProvider = nil
	cfg.PGBouncerMode = true
	cfg.Tracer = nil
	if log != nil {
		cfg.Logger = NewLoggerAdapter(log)
	} else {
		cfg.Logger = nil
	}
	return cfg
}

// OpenPool is the only connection constructor this module exposes — a
// thin wrap of pgcommon.NewPool so a future schema cannot bypass
// platform-pgcommon with a raw pgxpool. cmd/server does not call this
// (HLD §5.4: no database). Callers that do open a pool close it with
// (*pgcommon.Pool).Close, same as iam-user-profile / iam-org-membership.
func OpenPool(ctx context.Context, cfg pgcommon.Config) (*pgcommon.Pool, error) {
	return pgcommon.NewPool(ctx, cfg)
}

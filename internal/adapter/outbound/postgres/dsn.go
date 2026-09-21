// Package postgres is the outbound adapter for platform-pgcommon: DSN
// assembly, Zap logger adapter, OTel query tracer, and NewPool. This
// service has no database (HLD §5.4) — cmd/server loads the same
// ConfigFromEnv / DSNFromEnv / PoolConfig path iam-user-profile and
// iam-org-membership use, then skips NewPool / migrate / outbox. Any
// future schema would open exclusively through OpenPool.
package postgres

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-pgcommon/pkg/pgcommon"
)

// DSNFromEnv builds a PostgreSQL connection URL by delegating
// host/port/user/password/dbname/sslmode parsing and DSN assembly to
// pgcommon.ConfigFromEnv() — the same DATABASE_URL / PG_* vars
// platform-pgcommon reads. Mirrors iam-user-profile /
// iam-org-membership / iam-tender-acl. Warnings from ConfigFromEnv are
// surfaced at the composition root (cmd/server); this helper only
// returns the DSN string.
func DSNFromEnv() string {
	cfg, _ := pgcommon.ConfigFromEnv()
	if os.Getenv("DATABASE_URL") != "" {
		// DATABASE_URL is returned verbatim by pgcommon.ConfigFromEnv —
		// set statement_timeout via its own query string, not appended here.
		return cfg.DSN
	}
	return ApplyStatementTimeout(cfg.DSN)
}

// SystemDSNFromEnv returns the DSN for a privileged BYPASSRLS pool, matching
// iam-user-profile / iam-org-membership. Falls back to DSNFromEnv() when
// SYSTEM_DATABASE_URL is unset. cmd/server does not open this pool
// (HLD §5.4); the helper exists so a future schema cannot assemble a
// second DSN outside platform-pgcommon.
func SystemDSNFromEnv() string {
	if dsn := os.Getenv("SYSTEM_DATABASE_URL"); dsn != "" {
		return dsn
	}
	return DSNFromEnv()
}

// MigrationDSNFromEnv returns the DSN for schema migrations. Migrations
// must bypass PgBouncer because the runner uses session-scoped
// pg_advisory_lock. MIGRATION_DATABASE_URL falls back to DSNFromEnv().
// cmd/server does not run migrate.Runner (HLD §5.4).
func MigrationDSNFromEnv() string {
	if dsn := os.Getenv("MIGRATION_DATABASE_URL"); dsn != "" {
		return ApplyStatementTimeout(dsn)
	}
	return DSNFromEnv()
}

// ApplyStatementTimeout appends a server-side statement_timeout option to
// dsn so a hung query releases its pool connection. PG_STATEMENT_TIMEOUT
// accepts a Go duration string (e.g. "5s"). This has no pgcommon equivalent
// — pgcommon.Config has no statement-timeout field — so it is a small
// extension on the pgcommon-built DSN, identical to the siblings.
func ApplyStatementTimeout(dsn string) string {
	if dsn == "" {
		return dsn
	}
	if strings.Contains(dsn, "statement_timeout") {
		return dsn
	}
	if t := os.Getenv("PG_STATEMENT_TIMEOUT"); t != "" {
		if d, err := time.ParseDuration(t); err == nil && d > 0 {
			sep := "&"
			if !strings.Contains(dsn, "?") {
				sep = "?"
			}
			dsn += fmt.Sprintf("%soptions=-c%%20statement_timeout%%3D%d", sep, d.Milliseconds())
		}
	}
	return dsn
}

package postgres

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDSNFromEnv_UsesDatabaseURLShortcutWhenSet(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x:y@override.example:5432/appdb?sslmode=disable")
	assert.Equal(t,
		"postgres://x:y@override.example:5432/appdb?sslmode=disable",
		DSNFromEnv(),
		"DATABASE_URL shortcut short-circuits before any component parsing")
}

func TestDSNFromEnv_BuildsFromComponents(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PG_STATEMENT_TIMEOUT", "")
	t.Setenv("PG_HOST", "db.internal")
	t.Setenv("PG_PORT", "6432")
	t.Setenv("PG_USER", "authz_app")
	t.Setenv("PG_PASSWORD", "secret")
	t.Setenv("PG_DBNAME", "authz")
	t.Setenv("PG_SSLMODE", "require")

	dsn := DSNFromEnv()
	assert.True(t, strings.HasPrefix(dsn, "postgres://"))
	assert.Contains(t, dsn, "authz_app:secret")
	assert.Contains(t, dsn, "@db.internal:6432/authz")
	assert.Contains(t, dsn, "sslmode=require")
}

func TestDSNFromEnv_EmptyWhenUserAndDBMissing(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PG_USER", "")
	t.Setenv("PG_DBNAME", "")
	t.Setenv("PG_STATEMENT_TIMEOUT", "")
	assert.Empty(t, DSNFromEnv())
}

func TestDSNFromEnv_AppendsStatementTimeoutWhenSet(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PG_USER", "authz_app")
	t.Setenv("PG_DBNAME", "authz")
	t.Setenv("PG_STATEMENT_TIMEOUT", "5s")
	assert.Contains(t, DSNFromEnv(), "statement_timeout%3D5000")
}

func TestDSNFromEnv_InvalidStatementTimeoutIgnored(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PG_USER", "authz_app")
	t.Setenv("PG_DBNAME", "authz")
	t.Setenv("PG_STATEMENT_TIMEOUT", "not-a-duration")
	assert.NotContains(t, DSNFromEnv(), "statement_timeout")
}

func TestDSNFromEnv_ZeroStatementTimeoutIgnored(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PG_USER", "authz_app")
	t.Setenv("PG_DBNAME", "authz")
	t.Setenv("PG_STATEMENT_TIMEOUT", "0s")
	assert.NotContains(t, DSNFromEnv(), "statement_timeout")
}

func TestSystemDSNFromEnv_UsesEnvVarWhenSet(t *testing.T) {
	const want = "postgres://sys:sys@sysdb:5432/authz?sslmode=disable"
	t.Setenv("SYSTEM_DATABASE_URL", want)
	assert.Equal(t, want, SystemDSNFromEnv())
}

func TestSystemDSNFromEnv_FallsBackToAppDSN(t *testing.T) {
	t.Setenv("SYSTEM_DATABASE_URL", "")
	t.Setenv("DATABASE_URL", "postgres://a:b@app.example:5432/authz")
	assert.Equal(t, DSNFromEnv(), SystemDSNFromEnv())
}

func TestMigrationDSNFromEnv_UsesMigrationVarWhenSet(t *testing.T) {
	t.Setenv("PG_STATEMENT_TIMEOUT", "")
	t.Setenv("MIGRATION_DATABASE_URL", "postgres://m:x@migrations.example:5432/authz")
	assert.Equal(t, "postgres://m:x@migrations.example:5432/authz", MigrationDSNFromEnv())
}

func TestMigrationDSNFromEnv_AppliesStatementTimeout(t *testing.T) {
	t.Setenv("MIGRATION_DATABASE_URL", "postgres://m:x@migrations.example:5432/authz?sslmode=disable")
	t.Setenv("PG_STATEMENT_TIMEOUT", "5s")
	assert.Contains(t, MigrationDSNFromEnv(), "statement_timeout%3D5000")
}

func TestMigrationDSNFromEnv_FallsBackToDSNFromEnv(t *testing.T) {
	t.Setenv("MIGRATION_DATABASE_URL", "")
	t.Setenv("DATABASE_URL", "postgres://a:b@app.example:5432/authz")
	assert.Equal(t, DSNFromEnv(), MigrationDSNFromEnv())
}

func TestApplyStatementTimeout_EmptyDSN(t *testing.T) {
	t.Setenv("PG_STATEMENT_TIMEOUT", "5s")
	assert.Empty(t, ApplyStatementTimeout(""))
}

func TestApplyStatementTimeout_AlreadyPresent(t *testing.T) {
	t.Setenv("PG_STATEMENT_TIMEOUT", "5s")
	in := "postgres://u:p@h/db?options=-c%20statement_timeout%3D1000"
	assert.Equal(t, in, ApplyStatementTimeout(in))
}

func TestApplyStatementTimeout_AddsQueryWhenMissing(t *testing.T) {
	t.Setenv("PG_STATEMENT_TIMEOUT", "250ms")
	got := ApplyStatementTimeout("postgres://u:p@h/db")
	assert.Contains(t, got, "?options=-c%20statement_timeout%3D250")
}

func TestApplyStatementTimeout_AppendsWithAmpersand(t *testing.T) {
	t.Setenv("PG_STATEMENT_TIMEOUT", "1s")
	got := ApplyStatementTimeout("postgres://u:p@h/db?sslmode=disable")
	assert.Contains(t, got, "&options=-c%20statement_timeout%3D1000")
}

func TestApplyStatementTimeout_UnsetEnvUnchanged(t *testing.T) {
	t.Setenv("PG_STATEMENT_TIMEOUT", "")
	in := "postgres://u:p@h/db?sslmode=disable"
	assert.Equal(t, in, ApplyStatementTimeout(in))
}

func TestApplyStatementTimeout_InvalidDurationIgnored(t *testing.T) {
	t.Setenv("PG_STATEMENT_TIMEOUT", "not-a-duration")
	in := "postgres://u:p@h/db?sslmode=disable"
	assert.Equal(t, in, ApplyStatementTimeout(in))
}

func TestApplyStatementTimeout_ZeroDurationIgnored(t *testing.T) {
	t.Setenv("PG_STATEMENT_TIMEOUT", "0s")
	in := "postgres://u:p@h/db?sslmode=disable"
	assert.Equal(t, in, ApplyStatementTimeout(in))
}

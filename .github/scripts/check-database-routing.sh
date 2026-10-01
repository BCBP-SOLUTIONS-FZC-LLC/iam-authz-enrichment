#!/usr/bin/env bash
# check-database-routing.sh — enforces that all database connections,
# configuration, and operations in iam-authz-enrichment pass through
# platform-pgcommon only.
#
# Rules:
#   CONNECTIONS  — no raw pgxpool.New / pgx.Connect / pgx.ParseConfig /
#                  sql.Open in production code; all pools opened via
#                  postgres.OpenPool (→ pgcommon.NewPool).
#   CONFIG       — no hand-rolled DSN strings; all DSN/pool config via
#                  pgcommon.ConfigFromEnv() / pgadapter.DSNFromEnv().
#   OPERATIONS   — no direct pgconn / pgx imports in internal/ or cmd/
#                  production files; all error classification via pgcommon
#                  helpers (IsConnectionException, IsInsufficientResources,
#                  IsPgError).
#   DRIVERS      — no "database/sql" or "github.com/lib/pq" imports anywhere
#                  in production code; pgcommon owns the pgx/v5 driver.
#
# Note: this service has NO database (HLD §5.4). The postgres/ adapter exists
# so a future schema cannot bypass pgcommon. cmd/server loads PoolConfig then
# skips NewPool / migrate / outbox — this script enforces that invariant too.
#
# Mirrors check-observability-routing.sh's pattern.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

FAIL=0
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC}  $1"; }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; FAIL=1; }

echo "=== Database routing check: all DB connections/config/ops must pass through platform-pgcommon ==="
echo ""

# ────────────────────────────────────────────────────────────────────────────
# CONNECTIONS — no raw pool/connection constructors in production code
# ────────────────────────────────────────────────────────────────────────────
echo "-- Connections: no raw pgxpool.New / pgx.Connect / pgx.ParseConfig --"
RAW_CONN=$(grep -rn 'pgxpool\.New\b\|pgx\.Connect\b\|pgx\.ParseConfig\b\|pgxpool\.ParseConfig\b' \
  internal/ cmd/ --include="*.go" | grep -v "_test.go" || true)
if [ -n "$RAW_CONN" ]; then
  fail "Raw pgxpool.New / pgx.Connect / pgx.ParseConfig found — use postgres.OpenPool (→ pgcommon.NewPool) instead:"
  echo "$RAW_CONN" | sed 's/^/    /'
else
  pass "No raw pgxpool.New / pgx.Connect / pgx.ParseConfig in production code"
fi

echo "-- Connections: no database/sql or lib/pq --"
SQL_OPEN=$(grep -rn '"database/sql"\|"github.com/lib/pq"' \
  internal/ cmd/ --include="*.go" | grep -v "_test.go" || true)
if [ -n "$SQL_OPEN" ]; then
  fail "database/sql or lib/pq found — this service uses pgx/v5 via platform-pgcommon only:"
  echo "$SQL_OPEN" | sed 's/^/    /'
else
  pass "No database/sql or lib/pq imports"
fi

echo "-- Connections: OpenPool is the only pool constructor exposed --"
BYPASS_OPEN=$(grep -rn 'pgcommon\.NewPool\b' internal/ cmd/ --include="*.go" | \
  grep -v "_test.go" | grep -v "postgres/pool\.go" || true)
if [ -n "$BYPASS_OPEN" ]; then
  fail "pgcommon.NewPool called directly outside postgres/pool.go — callers must use postgres.OpenPool:"
  echo "$BYPASS_OPEN" | sed 's/^/    /'
else
  pass "pgcommon.NewPool only called through postgres.OpenPool"
fi

# ────────────────────────────────────────────────────────────────────────────
# CONFIG — no hand-rolled DSNs; all config via pgcommon.ConfigFromEnv
# ────────────────────────────────────────────────────────────────────────────
echo "-- Config: no hand-rolled DSN strings bypassing pgcommon.ConfigFromEnv --"
HAND_DSN=$(grep -rn 'postgres://\|postgresql://' internal/ cmd/ \
  --include="*.go" | grep -v "_test.go" | grep -v "^\s*//" || true)
if [ -n "$HAND_DSN" ]; then
  fail "Hard-coded postgres:// / postgresql:// DSN found — use pgcommon.ConfigFromEnv() / postgres.DSNFromEnv():"
  echo "$HAND_DSN" | sed 's/^/    /'
else
  pass "No hand-rolled postgres:// DSN strings in production code"
fi

echo "-- Config: pgcommon.ConfigFromEnv is the sole pool-config source --"
RAW_CONFIG=$(grep -rn 'pgxpool\.Config{' internal/ cmd/ --include="*.go" | \
  grep -v "_test.go" || true)
if [ -n "$RAW_CONFIG" ]; then
  fail "pgxpool.Config{} literal found — use pgcommon.ConfigFromEnv() / postgres.PoolConfig() instead:"
  echo "$RAW_CONFIG" | sed 's/^/    /'
else
  pass "No raw pgxpool.Config{} literals in production code"
fi

# ────────────────────────────────────────────────────────────────────────────
# OPERATIONS — no direct pgconn / pgx / puddle imports in production code
# ────────────────────────────────────────────────────────────────────────────
echo "-- Operations: no direct pgx/pgconn/puddle imports in internal/ or cmd/ --"
DIRECT_PGX=$(grep -rn '"github.com/jackc/pgx\|"github.com/jackc/pgconn\|"github.com/jackc/puddle' \
  internal/ cmd/ --include="*.go" | grep -v "_test.go" | \
  grep -v "^\s*//" | grep -v ":[[:space:]]*//" || true)
if [ -n "$DIRECT_PGX" ]; then
  fail "Direct pgx/pgconn/puddle import found in production code — route all DB ops through platform-pgcommon:"
  echo "$DIRECT_PGX" | sed 's/^/    /'
else
  pass "No direct pgx/pgconn/puddle imports in production code"
fi

echo "-- Operations: error classification uses pgcommon helpers only --"
RAW_PGERR=$(grep -rn 'pgconn\.PgError\b\|\*pgconn\.PgError\b' \
  internal/ cmd/ --include="*.go" | grep -v "_test.go" || true)
if [ -n "$RAW_PGERR" ]; then
  fail "pgconn.PgError used directly — use pgcommon.IsPgError() / IsConnectionException() / IsInsufficientResources() instead:"
  echo "$RAW_PGERR" | sed 's/^/    /'
else
  pass "All PG error classification goes through pgcommon helpers"
fi

# ────────────────────────────────────────────────────────────────────────────
# SERVICE INVARIANT — this service has no database (HLD §5.4);
# NewPool / migrate / outbox must never be started from cmd/server
# ────────────────────────────────────────────────────────────────────────────
echo "-- Invariant: cmd/server does not call NewPool / migrate / outbox runner (HLD §5.4) --"
LIVE_POOL=$(grep -n 'postgres\.OpenPool\b\|pgcommon\.NewPool\b\|migrate\.Run\b\|outbox\.NewRunner\b\|outbox\.ApplySchema\b' \
  cmd/server/main.go 2>/dev/null | grep -v "^\s*//" | grep -v ":[[:space:]]*//" || true)
if [ -n "$LIVE_POOL" ]; then
  fail "cmd/server/main.go calls OpenPool / migrate / outbox runner — this service has no schema (HLD §5.4):"
  echo "$LIVE_POOL" | sed 's/^/    /'
else
  pass "cmd/server/main.go correctly skips OpenPool / migrate / outbox (HLD §5.4 — no schema)"
fi

# ────────────────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────────────────
echo ""
if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}All database routing checks passed.${NC}"
  echo "  Connections → postgres.OpenPool (→ pgcommon.NewPool)"
  echo "  Config      → pgcommon.ConfigFromEnv() / postgres.DSNFromEnv()"
  echo "  Operations  → pgcommon helpers (IsConnectionException / IsPgError / ...)"
  echo "  Invariant   → no live pool / migrate / outbox (HLD §5.4 — no schema)"
  exit 0
else
  echo -e "${RED}Database routing check FAILED — see violations above.${NC}"
  echo "All DB connections, configuration, and operations must pass through platform-pgcommon only."
  exit 1
fi

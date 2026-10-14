#!/usr/bin/env bash
# check-metrics-naming.sh — enforces the Enterprise Platform Observability Standard
# for iam-authz-enrichment's Tier 3 service-specific metrics.
#
# Rules (Tier 3 service-specific):
#   1. All metric names must use the iam_authz_enrichment_ prefix.
#   2. Counter metrics must end with _total.
#   3. Histogram metrics must end with _seconds.
#   4. No legacy authz_* (unprefixed) metric names may remain.
#
# Mirrors check-observability-routing.sh and check-database-routing.sh patterns.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

FAIL=0
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC}  $1"; }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; FAIL=1; }

echo "=== Metrics naming check: Enterprise Platform Observability Standard ==="
echo ""

# ── Rule 1: No legacy authz_* unprefixed metric names in production code ──
echo "-- No legacy authz_* metric names in recorder.go --"
LEGACY=$(grep -n '"authz_' internal/adapter/outbound/metrics/recorder.go || true)
if [ -n "$LEGACY" ]; then
  fail "Legacy authz_* metric name found in recorder.go — use iam_authz_enrichment_* (Tier 3):"
  echo "$LEGACY" | sed 's/^/    /'
else
  pass "No legacy authz_* names in recorder.go"
fi

# ── Rule 2: No legacy authz_* in alert/rule YAML files ──
echo "-- No legacy authz_* metric names in deploy/monitoring/ --"
LEGACY_YAML=$(grep -rn '"authz_\|authz_[a-z]' deploy/monitoring/ deploy/helm/templates/ \
  --include="*.yml" --include="*.yaml" | grep -v "iam_authz_enrichment" || true)
if [ -n "$LEGACY_YAML" ]; then
  fail "Legacy authz_* metric name found in deploy files — update to iam_authz_enrichment_*:"
  echo "$LEGACY_YAML" | sed 's/^/    /'
else
  pass "No legacy authz_* names in deploy/ YAML files"
fi

# ── Rule 3: All Tier 3 metrics use the iam_authz_enrichment_ prefix ──
echo "-- All service metrics use iam_authz_enrichment_ prefix --"
# Extract Name: "..." lines from recorder.go and verify prefix
BAD_PREFIX=$(grep -n 'Name:.*"[a-z]' internal/adapter/outbound/metrics/recorder.go | \
  grep -v 'iam_authz_enrichment_' || true)
if [ -n "$BAD_PREFIX" ]; then
  fail "Metric name without iam_authz_enrichment_ prefix in recorder.go:"
  echo "$BAD_PREFIX" | sed 's/^/    /'
else
  pass "All metric names use iam_authz_enrichment_ prefix"
fi

# ── Rule 4: Counter metrics end with _total ──
echo "-- Counter metrics end with _total --"
# Check that every Name: line inside a NewCounter*/NewCounterVec block ends with _total.
# Strategy: track when we enter a NewCounter call, then check the next Name: line.
BAD_COUNTER=$(awk '
  /NewCounter/ { in_counter=1 }
  in_counter && /Name:/ {
    if ($0 !~ /_total"/) { print NR": "$0 }
    in_counter=0
  }
' internal/adapter/outbound/metrics/recorder.go || true)
if [ -n "$BAD_COUNTER" ]; then
  fail "Counter metric without _total suffix:"
  echo "$BAD_COUNTER" | sed 's/^/    /'
else
  pass "All counter metrics end with _total"
fi

# ── Rule 5: Histogram metrics end with _seconds ──
echo "-- Histogram metrics end with _seconds --"
# Check that every Name: line inside a NewHistogram*/NewHistogramVec block ends with _seconds.
BAD_HIST=$(awk '
  /NewHistogram/ { in_hist=1 }
  in_hist && /Name:/ {
    if ($0 !~ /_seconds"/) { print NR": "$0 }
    in_hist=0
  }
' internal/adapter/outbound/metrics/recorder.go || true)
if [ -n "$BAD_HIST" ]; then
  fail "Histogram metric without _seconds suffix:"
  echo "$BAD_HIST" | sed 's/^/    /'
else
  pass "All histogram metrics end with _seconds"
fi

# ── Rule 6: No high-cardinality label values prohibited by the standard ──
echo "-- No high-cardinality labels (user_id, tenant_id, email, request_id) --"
HIGH_CARD=$(grep -rn '"user_id"\|"tenant_id"\|"email"\|"request_id"\|"event_id"\|"session_id"' \
  internal/adapter/outbound/metrics/recorder.go || true)
if [ -n "$HIGH_CARD" ]; then
  fail "High-cardinality label found in recorder.go — prohibited by the Observability Standard:"
  echo "$HIGH_CARD" | sed 's/^/    /'
else
  pass "No high-cardinality labels in metric definitions"
fi

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}All metrics naming checks passed.${NC}"
  echo "  Namespace : iam_authz_enrichment_* (Tier 3 service-specific)"
  echo "  Counters  : _total suffix"
  echo "  Histograms: _seconds suffix"
  echo "  Labels    : no high-cardinality values"
  exit 0
else
  echo -e "${RED}Metrics naming check FAILED — see violations above.${NC}"
  exit 1
fi

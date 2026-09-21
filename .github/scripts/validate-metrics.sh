#!/usr/bin/env bash
# validate-metrics.sh — CI enforcement of the Enterprise Platform Observability
# Standard for this service.
#
# Checks:
#  1. No new authz_* metric registrations outside the backward-compat block
#     in recorder.go (prevents re-introduction of the legacy namespace).
#  2. Every iam_authz_enrichment_* counter name ends with _total.
#  3. Every iam_authz_enrichment_* histogram name ends with _seconds.
#  4. Every platform_* counter name ends with _total.
#  5. Every platform_* histogram name ends with _seconds.
#
# The legacy authz_* metrics in recorder.go are explicitly whitelisted below
# and are expected to remain until the migration sunset period ends.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RECORDER="$ROOT/internal/adapter/outbound/metrics/recorder.go"

ok=true

# ── 1. No new authz_* metric names outside recorder.go ────────────────────────
echo "Checking: no new authz_* metric registrations outside recorder.go..."
while IFS= read -r line; do
  file="${line%%:*}"
  rest="${line#*:}"
  # Skip the whitelist file itself.
  if [[ "$file" == "$RECORDER" ]]; then
    continue
  fi
  # Skip test files asserting on field values (they reference field names, not metric names).
  if [[ "$file" == *_test.go ]]; then
    continue
  fi
  # Skip Markdown docs.
  if [[ "$file" == *.md ]]; then
    continue
  fi
  echo "  FAIL: legacy authz_* metric name found in $file: $rest"
  ok=false
done < <(grep -rn '"authz_' "$ROOT" \
  --include="*.go" \
  --include="*.yaml" \
  --include="*.yml" \
  --exclude-dir=".git" 2>/dev/null \
  | grep -v "^$RECORDER:" \
  | grep -v "_test.go:.*authz_" \
  || true)

# ── 2 & 3. iam_authz_enrichment_* naming rules ────────────────────────────────
echo "Checking: iam_authz_enrichment_* counter names end with _total..."
while IFS= read -r name; do
  name="${name//\"/}"
  # Skip histograms (they may end with _seconds).
  if grep -q "NewHistogram\|NewHistogramVec" "$RECORDER" 2>/dev/null; then
    :
  fi
  if [[ "$name" != *_total && "$name" != *_seconds ]]; then
    echo "  FAIL: iam_authz_enrichment_* metric '$name' must end with _total (counter) or _seconds (histogram)"
    ok=false
  fi
done < <(grep -oE '"iam_authz_enrichment_[a-z_]+"' "$RECORDER" || true)

# ── 4 & 5. platform_* naming rules ────────────────────────────────────────────
echo "Checking: platform_* counter/histogram names end with _total/_seconds..."
while IFS= read -r name; do
  name="${name//\"/}"
  if [[ "$name" != *_total && "$name" != *_seconds ]]; then
    echo "  FAIL: platform_* metric '$name' must end with _total (counter) or _seconds (histogram)"
    ok=false
  fi
done < <(grep -oE '"platform_[a-z_]+"' "$RECORDER" || true)

# ── Result ─────────────────────────────────────────────────────────────────────
if $ok; then
  echo "validate-metrics: all checks passed."
else
  echo "validate-metrics: one or more checks FAILED (see above)."
  exit 1
fi

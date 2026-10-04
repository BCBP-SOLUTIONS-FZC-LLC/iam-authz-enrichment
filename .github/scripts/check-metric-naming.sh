#!/usr/bin/env bash
# Enforces the Enterprise Platform Observability Standard's construction and
# naming rules against internal/adapter/outbound/metrics/ — the only package
# that builds Prometheus collectors in this service. (metricslint.sh validates
# the emitted scrape; this pins how the collectors are built.) Ported from
# iam-org-membership's script of the same name.
#
# Rules:
#   - no collector is built with prometheus.New* or promauto in non-test code:
#     every one comes from a gincommon constructor, which injects the
#     {domain, service, environment} const labels and validates the name
#   - New() builds only Tier 3 iam_authz_enrichment_* names through the
#     builder (counterVec / counter / histogram): snake_case, _total on
#     counters, _seconds on histograms
#
# Does NOT validate the classification itself (shared vs. service-specific) —
# that is a review-time call per the standard's decision tree.
set -euo pipefail

cd "$(dirname "$0")/../.."

DIR="internal/adapter/outbound/metrics"
test -d "$DIR" || {
  echo "::error file=${DIR}::metrics package not found"
  exit 1
}

python3 - "$DIR" <<'PYEOF'
import glob
import re
import sys

pkg = sys.argv[1]
errors = []
sources = {p: open(p, encoding="utf-8").read() for p in sorted(glob.glob(f"{pkg}/*.go")) if not p.endswith("_test.go")}

for path, text in sources.items():
    for m in re.finditer(r"prometheus\.New(Counter|CounterVec|Gauge|GaugeVec|Histogram|HistogramVec|Summary|SummaryVec)\(|promauto\.", text):
        line = text[: m.start()].count("\n") + 1
        errors.append(f"{path}:{line}: {m.group(0)} — build collectors with gincommon's constructors (NewCounterVec / NewCounter / NewHistogramVec)")

recorder = sources.get(f"{pkg}/recorder.go", "")
collectors = re.findall(r'b\.(counterVec|counter|histogram)\("([^"]+)"', recorder)
if not collectors:
    errors.append(f"{pkg}/recorder.go: New() builds no collectors through the builder")
for kind, name in collectors:
    if not re.fullmatch(r"iam_authz_enrichment_[a-z0-9_]+", name):
        errors.append(f'"{name}": Tier 3 collectors must be iam_authz_enrichment_<snake_case>')
    if kind.startswith("counter") and not name.endswith("_total"):
        errors.append(f'"{name}": a counter must end in _total')
    if kind == "histogram" and not name.endswith("_seconds"):
        errors.append(f'"{name}": a histogram must end in _seconds')

if errors:
    for e in errors:
        print(f"::error::{e}")
    print(f"\n{len(errors)} violation(s) across {len(collectors)} collectors.")
    sys.exit(1)
print(f"  ✔  {len(collectors)} collectors — all built with gincommon constructors; naming and suffix rules OK")
PYEOF

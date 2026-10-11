#!/usr/bin/env bash
# Enforces the Enterprise Platform Observability Standard's governance rules
# 11/12: a registry metric whose status is still `proposed` (submitted, not
# ratified) must not be the live query target of an alert or recording rule
# unless that rule is labelled `metric_status: proposed`, so routing can treat
# it accordingly.
#
# iam-org-membership keeps a local PlatformRegistry (registry.go) for this;
# this service owns no shared metrics, so the status comes straight from the
# Platform Observability Registry in the pinned platform-gincommon.
# Mentioning a proposed name in a comment is fine; using it in `expr:` without
# the label is not.
set -euo pipefail

cd "$(dirname "$0")/../.."

registry="$(go list -m -f '{{.Dir}}' github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon)/internal/obsregistry/registry.json"

python3 - "$registry" deploy/monitoring/app-alerts.yml <<'PYEOF'
import json
import re
import sys

registry_path, *rule_files = sys.argv[1:]
proposed = {m["name"] for m in json.load(open(registry_path, encoding="utf-8"))["metrics"] if m.get("status") == "proposed"}

try:
    import yaml  # PyYAML ships with the GitHub runner images
except ImportError:
    sys.exit("::error::PyYAML is required (pip install pyyaml)")

fail = 0
for path in rule_files:
    doc = yaml.safe_load(open(path, encoding="utf-8"))
    for group in doc.get("groups", []):
        for rule in group.get("rules", []):
            expr = rule.get("expr", "")
            used = {n for n in proposed if re.search(rf"\b{re.escape(n)}(_bucket|_sum|_count)?\b", expr)}
            labelled = (rule.get("labels") or {}).get("metric_status") == "proposed"
            if used and not labelled:
                name = rule.get("alert") or rule.get("record")
                print(f"::error file={path}::{name} queries proposed metric(s) {sorted(used)} without `metric_status: proposed`")
                fail = 1
if fail:
    sys.exit(1)
print(f"OK: no proposed registry metric is queried by an unlabelled rule in {', '.join(rule_files)}")
PYEOF
